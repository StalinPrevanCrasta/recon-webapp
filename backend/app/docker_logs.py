import asyncio
import json
import os
import queue
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable

try:
    import docker
except Exception:  # pragma: no cover - exercised when dependency missing in container-less tests
    docker = None

LOG_VIEWER_DISABLED = "Docker log viewer is disabled."
DOCKER_UNAVAILABLE = "Docker logs are unavailable because the API cannot access the Docker daemon."
DEFAULT_SERVICES = "backend,worker,frontend,redis"
MAX_CLIENTS = 5
_client_lock = threading.Lock()
_active_clients = 0

DISPLAY_NAMES = {
    "backend": "API",
    "worker": "Celery Worker",
    "frontend": "Frontend",
    "redis": "Redis",
}
LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\b", re.I)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
REDACTION_PATTERNS = [
    (re.compile(r"(Authorization\s*:\s*Bearer\s+)[^\s'\"]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(Authorization\s*:\s*)[^\r\n]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(Cookie\s*:\s*)[^\r\n]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"\b(password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,&;]+", re.I), r"\1=[REDACTED]"),
    (re.compile(r"\b([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\b"), "[REDACTED-JWT]"),
    (re.compile(r"(postgres(?:ql)?://[^:\s/@]+:)[^@\s]+(@[^\s]+)", re.I), r"\1[REDACTED]\2"),
    (re.compile(r"(redis://[^:\s/@]*:)[^@\s]+(@[^\s]+)", re.I), r"\1[REDACTED]\2"),
    (re.compile(r"(https?://[^:\s/@]+:)[^@\s]+(@[^\s]+)", re.I), r"\1[REDACTED]\2"),
]


@dataclass
class LogEvent:
    timestamp: str
    container: str
    stream: str
    level: str
    message: str


def viewer_enabled() -> bool:
    return os.getenv("ENABLE_DOCKER_LOG_VIEWER", "false").lower() in {"1", "true", "yes", "on"}


def redaction_enabled() -> bool:
    return os.getenv("DOCKER_LOG_REDACTION", "true").lower() not in {"0", "false", "no", "off"}


def allowed_services() -> list[str]:
    raw = os.getenv("DOCKER_LOG_ALLOWED_SERVICES", DEFAULT_SERVICES)
    services = []
    for item in raw.split(","):
        service = item.strip()
        if service and re.fullmatch(r"[a-zA-Z0-9_.-]+", service):
            services.append(service)
    return services


def default_tail() -> int:
    return clamp_tail(os.getenv("DOCKER_LOG_TAIL", "200"))


def max_tail() -> int:
    try:
        return max(1, int(os.getenv("DOCKER_LOG_MAX_TAIL", "2000")))
    except ValueError:
        return 2000


def clamp_tail(value: int | str | None) -> int:
    try:
        tail = int(value) if value is not None else 200
    except ValueError:
        tail = 200
    return max(0, min(tail, max_tail()))


def validate_container_selection(container: str | None) -> list[str]:
    selected = (container or "all").strip()
    services = allowed_services()
    if selected == "all":
        return services
    if selected not in services:
        raise ValueError("Unknown or unauthorized log container.")
    return [selected]


def docker_client():
    if docker is None:
        raise RuntimeError(DOCKER_UNAVAILABLE)
    try:
        return docker.from_env()
    except Exception as exc:
        raise RuntimeError(DOCKER_UNAVAILABLE) from exc


def find_container(client, service: str):
    containers = client.containers.list(all=True, filters={"label": f"com.docker.compose.service={service}"})
    return containers[0] if containers else None


def list_allowed_containers() -> list[dict]:
    client = docker_client()
    rows = []
    for service in allowed_services():
        container = find_container(client, service)
        rows.append({
            "id": service,
            "display_name": DISPLAY_NAMES.get(service, service.replace("-", " ").title()),
            "status": getattr(container, "status", "missing") if container else "missing",
        })
    return rows


def sanitize_message(message: str) -> str:
    safe = CONTROL_RE.sub("", message).replace("\r", "")
    if redaction_enabled():
        for pattern, replacement in REDACTION_PATTERNS:
            safe = pattern.sub(replacement, safe)
    return safe


def detect_level(message: str) -> str:
    match = LEVEL_RE.search(message)
    if not match:
        return "INFO"
    level = match.group(1).upper()
    return "WARNING" if level == "WARN" else "CRITICAL" if level == "FATAL" else level


def parse_log_line(service: str, raw: bytes | str, stream: str = "stdout") -> LogEvent:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    text = text.rstrip("\n")
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if len(text) > 31 and text[4:5] == "-" and "T" in text[:32]:
        first, rest = text.split(" ", 1) if " " in text else (text, "")
        timestamp, text = first, rest
    message = sanitize_message(text)
    return LogEvent(timestamp=timestamp, container=service, stream=stream, level=detect_level(message), message=message)


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def acquire_client() -> bool:
    global _active_clients
    with _client_lock:
        if _active_clients >= MAX_CLIENTS:
            return False
        _active_clients += 1
        return True


def release_client() -> None:
    global _active_clients
    with _client_lock:
        _active_clients = max(0, _active_clients - 1)


def reader_thread(client, service: str, tail: int, stop: threading.Event, out: queue.Queue) -> None:
    try:
        container = find_container(client, service)
        if not container:
            out.put(("error", {"container": service, "message": "Approved service is missing or stopped."}))
            return
        if hasattr(client, "api") and hasattr(container, "id"):
            try:
                stream = client.api.logs(container.id, stream=True, follow=True, tail=tail, timestamps=True, stdout=True, stderr=True, demux=True)
            except TypeError:
                # docker-py 7.x logs() has no demux parameter; fall back to the safe high-level API.
                stream = container.logs(stream=True, follow=True, tail=tail, timestamps=True, stdout=True, stderr=True)
        else:
            stream = container.logs(stream=True, follow=True, tail=tail, timestamps=True, stdout=True, stderr=True)
        for line in stream:
            if stop.is_set():
                break
            stream_name = "stdout"
            if isinstance(line, tuple):
                stdout, stderr = line
                if stderr is not None:
                    line = stderr
                    stream_name = "stderr"
                else:
                    line = stdout or b""
            out.put(("log", parse_log_line(service, line, stream_name).__dict__))
    except Exception:
        out.put(("error", {"container": service, "message": DOCKER_UNAVAILABLE}))


async def stream_logs(container: str = "all", tail: int | str | None = None):
    services = validate_container_selection(container)
    if not acquire_client():
        yield sse("error", {"message": "Too many active log viewers. Try again later."})
        return
    stop = threading.Event()
    q: queue.Queue = queue.Queue(maxsize=10000)
    threads: list[threading.Thread] = []
    try:
        client = docker_client()
        tail_value = clamp_tail(tail if tail is not None else default_tail())
        for service in services:
            thread = threading.Thread(target=reader_thread, args=(client, service, tail_value, stop, q), daemon=True)
            thread.start()
            threads.append(thread)
        yield sse("ready", {"containers": services, "tail": tail_value})
        last_heartbeat = asyncio.get_running_loop().time()
        while not stop.is_set():
            now = asyncio.get_running_loop().time()
            try:
                event, data = await asyncio.to_thread(q.get, True, 1)
                yield sse(event, data)
            except queue.Empty:
                if now - last_heartbeat >= 15:
                    yield sse("heartbeat", {"timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z")})
                    last_heartbeat = now
                if threads and not any(t.is_alive() for t in threads):
                    break
    finally:
        stop.set()
        release_client()
