import asyncio
import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import docker_logs


class FakeContainer:
    status = "running"

    def __init__(self, lines=None):
        self.lines = lines or []

    def logs(self, **kwargs):
        for line in self.lines:
            yield line


class FakeContainers:
    def __init__(self, mapping):
        self.mapping = mapping

    def list(self, all=True, filters=None):
        label = (filters or {}).get("label", "")
        service = label.split("=", 1)[1] if "=" in label else ""
        container = self.mapping.get(service)
        return [container] if container else []


class FakeClient:
    def __init__(self, mapping):
        self.containers = FakeContainers(mapping)


def enable_logs(monkeypatch):
    monkeypatch.setenv("ENABLE_DOCKER_LOG_VIEWER", "true")
    monkeypatch.setenv("DOCKER_LOG_ALLOWED_SERVICES", "backend,worker,frontend,redis")


def test_viewer_disabled_returns_403(monkeypatch):
    monkeypatch.setenv("ENABLE_DOCKER_LOG_VIEWER", "false")
    response = TestClient(app).get("/api/system/logs/containers")
    assert response.status_code == 403


def test_container_list_only_exposes_allowlisted_services(monkeypatch):
    enable_logs(monkeypatch)
    monkeypatch.setattr(docker_logs, "docker_client", lambda: FakeClient({"backend": FakeContainer(), "worker": FakeContainer()}))

    response = TestClient(app).get("/api/system/logs/containers")

    assert response.status_code == 200
    rows = response.json()["containers"]
    assert [row["id"] for row in rows] == ["backend", "worker", "frontend", "redis"]
    assert rows[0]["display_name"] == "API"
    assert rows[2]["status"] == "missing"


def test_arbitrary_container_input_is_rejected(monkeypatch):
    enable_logs(monkeypatch)
    response = TestClient(app).get("/api/system/logs/stream?container=/var/run/docker.sock")
    assert response.status_code == 404


def test_tail_limit_is_enforced(monkeypatch):
    monkeypatch.setenv("DOCKER_LOG_MAX_TAIL", "2000")
    assert docker_logs.clamp_tail(999999) == 2000
    assert docker_logs.clamp_tail("bad") == 200


def test_log_sanitization_and_redaction(monkeypatch):
    monkeypatch.setenv("DOCKER_LOG_REDACTION", "true")
    msg = "INFO Authorization: Bearer abcdef123 password=hunter2 postgres://u:secret@db/app\x00"
    safe = docker_logs.sanitize_message(msg)
    assert "hunter2" not in safe
    assert "secret@" not in safe
    assert "Authorization:" in safe
    assert "[REDACTED]" in safe
    assert "\x00" not in safe


def test_parse_log_line_is_text_safe(monkeypatch):
    monkeypatch.setenv("DOCKER_LOG_REDACTION", "true")
    event = docker_logs.parse_log_line("worker", b"2026-07-18T15:12:31.123Z ERROR token=abcdef1234567890abcdef\n")
    assert event.container == "worker"
    assert event.level == "ERROR"
    assert event.message == "ERROR token=[REDACTED]"


def test_parse_log_line_preserves_stream_name():
    event = docker_logs.parse_log_line("backend", b"WARNING on stderr\n", "stderr")
    assert event.stream == "stderr"
    assert event.level == "WARNING"


def test_docker_unavailable_error_is_sanitized(monkeypatch):
    enable_logs(monkeypatch)
    monkeypatch.setattr(docker_logs, "docker_client", lambda: (_ for _ in ()).throw(RuntimeError(docker_logs.DOCKER_UNAVAILABLE)))
    with pytest.raises(RuntimeError, match="Docker logs are unavailable"):
        docker_logs.list_allowed_containers()


def test_heartbeat_event_format(monkeypatch):
    payload = docker_logs.sse("heartbeat", {"timestamp": "now"})
    assert payload.startswith("event: heartbeat\n")
    assert '"timestamp": "now"' in payload


def test_no_shell_execution_in_docker_logs_module():
    import inspect
    source = inspect.getsource(docker_logs)
    assert "shell=True" not in source
    assert "subprocess" not in source
