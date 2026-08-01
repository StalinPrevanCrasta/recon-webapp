import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ISO_TIMESTAMP_RE = re.compile(r"(?i)^\d{4}-\d{2}-\d{2}(?:[t_ -]\d{2}(?::?\d{2}){1,2}(?:\.\d+)?z?)?$")
EPOCH_RE = re.compile(r"^\d{10}(?:\d{3})?$")
HEX_HASH_RE = re.compile(r"(?i)^[0-9a-f]{16,}$")
TOKEN_HASH_RE = re.compile(r"(?i)^[a-z0-9_-]{24,}$")
LOCALE_RE = re.compile(r"(?i)^[a-z]{2,3}(?:[-_][a-z]{2,4})$")
STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".csv", ".doc", ".docx", ".eot", ".gif", ".gz",
    ".ico", ".jpeg", ".jpg", ".map", ".mov", ".mp3", ".mp4", ".otf", ".pdf", ".png",
    ".ppt", ".pptx", ".rar", ".svg", ".tar", ".tif", ".tiff", ".ttf", ".wav", ".webp",
    ".woff", ".woff2", ".xls", ".xlsx", ".xml", ".zip",
}
MARKETING_SEGMENTS = {
    "about", "asset", "assets", "blog", "careers", "company", "contact", "events", "images",
    "investors", "legal", "news", "partner", "partners", "press", "privacy", "resources",
    "solutions", "support", "terms",
}
API_SEGMENTS = {
    "api", "graphql", "rest", "rpc", "service", "services", "swagger", "openapi", "wp-json",
}


def canonicalize_url(value: str | None, *, drop_fragment: bool = True) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return raw
    scheme = parts.scheme.lower()
    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return raw
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" if port is None or default_port else f"[{host}]:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "")
    fragment = "" if drop_fragment else parts.fragment
    return urlunsplit((scheme, netloc, path, parts.query, fragment))


def canonical_asset_key(value: str | None) -> str:
    canonical = canonicalize_url(value)
    try:
        parts = urlsplit(canonical)
    except ValueError:
        return canonical
    if parts.scheme in {"http", "https"} and parts.netloc:
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return canonical


def _normalize_segment(segment: str) -> str:
    if UUID_RE.fullmatch(segment):
        return "{uuid}"
    if ISO_TIMESTAMP_RE.fullmatch(segment) or EPOCH_RE.fullmatch(segment):
        return "{timestamp}"
    if HEX_HASH_RE.fullmatch(segment) or (
        TOKEN_HASH_RE.fullmatch(segment)
        and any(char.isdigit() for char in segment)
        and any(char.isalpha() for char in segment)
    ):
        return "{hash}"
    if LOCALE_RE.fullmatch(segment):
        return "{locale}"
    if segment.isdigit():
        return "{id}"
    return segment


def normalize_path_pattern(value: str | None) -> str:
    raw = str(value or "").strip()
    try:
        path = urlsplit(raw).path if "://" in raw else raw.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        path = raw.split("?", 1)[0]
    path = re.sub(r"/{2,}", "/", path or "/")
    if not path.startswith("/"):
        path = "/" + path
    trailing = path.endswith("/") and path != "/"
    normalized = "/".join(_normalize_segment(part) for part in path.split("/"))
    if trailing and not normalized.endswith("/"):
        normalized += "/"
    return normalized or "/"


def canonical_endpoint_key(value: str | None, method: str = "GET") -> tuple[str, str, str]:
    return canonical_asset_key(value), normalize_path_pattern(value), str(method or "GET").upper()


def normalize_indicator(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://", "//", "/")):
        candidate = f"https:{raw}" if raw.startswith("//") else raw
        try:
            parts = urlsplit(candidate)
            query = [
                (key.lower(), "{value}")
                for key, _ in parse_qsl(parts.query, keep_blank_values=True)
                if key.lower() not in {"_", "cache", "cachebuster", "cb", "t", "timestamp", "ts", "v", "version"}
            ]
            normalized = urlunsplit((
                parts.scheme.lower(),
                parts.netloc.lower(),
                normalize_path_pattern(parts.path),
                urlencode(sorted(query)),
                "",
            ))
            return normalized if parts.netloc else normalize_path_pattern(parts.path)
        except ValueError:
            pass
    tokens = re.split(r"([/:?=&\s]+)", raw)
    return "".join(_normalize_segment(token) if token and not re.fullmatch(r"[/:?=&\s]+", token) else token for token in tokens).lower()


def is_static_or_marketing_url(value: str | None) -> bool:
    try:
        path = urlsplit(str(value or "")).path.lower()
    except ValueError:
        path = str(value or "").lower()
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if suffix in STATIC_EXTENSIONS:
        return True
    segments = {part for part in path.split("/") if part}
    return bool(segments & MARKETING_SEGMENTS) and not bool(segments & API_SEGMENTS)


def is_api_like_endpoint(value: str | None) -> bool:
    if is_static_or_marketing_url(value):
        return False
    try:
        path = urlsplit(str(value or "")).path.lower()
    except ValueError:
        path = str(value or "").lower()
    segments = {part for part in path.split("/") if part}
    return bool(segments & API_SEGMENTS) or bool(re.search(r"/v\d+(?:/|$)", path))


def stable_fingerprint(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
