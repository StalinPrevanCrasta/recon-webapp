import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import gzip
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urljoin, urlparse

import httpx as pyhttpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import models
from app.recon.runner import CommandError, CommandRunner, run_command as _run_command
from app.recon.normalization import (
    canonical_asset_key, canonical_endpoint_key, canonicalize_url, is_api_like_endpoint,
    is_static_or_marketing_url, normalize_indicator, normalize_path_pattern, stable_fingerprint,
)
from app.recon.wrappers import (
    build_amass_command, build_arjun_command, build_ffuf_command, build_gau_command, build_gowitness_command, build_httpx_command, build_katana_command, build_naabu_command,
    build_puredns_command, build_subfinder_command, normalize_content_path, parse_ffuf_json, parse_httpx_jsonl,
    parse_naabu_jsonl, build_wappalyzer_command, parse_wappalyzer_json, extract_endpoint_urls, extract_parameters_from_urls, parse_arjun_json,
    build_nuclei_command, parse_nuclei_jsonl,
)
from app.recon.wordlists import resolve_ffuf_wordlist
from app.settings_store import load_settings

logger = logging.getLogger(__name__)

# Exposed as a test seam. Production scan commands use CommandRunner so
# cancellation/process tracking stays out of individual call sites.
run_command = _run_command
SCAN_CONCURRENT_ENUM = int(os.getenv("SCAN_CONCURRENT_ENUM", "2"))
SCAN_FFUF_PARALLEL = int(os.getenv("SCAN_FFUF_PARALLEL", "2"))
SCAN_BATCH_SIZE = int(os.getenv("SCAN_BATCH_SIZE", "500"))
FFUF_RESULT_BATCH_SIZE = int(os.getenv("FFUF_RESULT_BATCH_SIZE", "50"))
JS_INTEL_BATCH_SIZE = int(os.getenv("JS_INTEL_BATCH_SIZE", "50"))
NUCLEI_RESULT_BATCH_SIZE = int(os.getenv("NUCLEI_RESULT_BATCH_SIZE", "50"))
PARAMETER_RESULT_BATCH_SIZE = int(os.getenv("PARAMETER_RESULT_BATCH_SIZE", "500"))

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
RAW_DIR = DATA_DIR / "raw"
SCREEN_DIR = DATA_DIR / "screenshots"
WORDLIST_DIR = DATA_DIR / "wordlists"
DEFAULT_RESOLVERS = DATA_DIR / "resolvers.txt"
WEB_PORTS = {80, 81, 3000, 3001, 5000, 5173, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443, 10443}
BUNDLED_TECH_WORDLISTS = {
    "php": Path("/app/wordlists/tech/php_wordlist.txt"),
    "wordpress": Path("/app/wordlists/tech/php_wordlist.txt"),
    "node": Path("/app/wordlists/tech/node_wordlist.txt"),
    "javascript": Path("/app/wordlists/tech/node_wordlist.txt"),
    "graphql": Path("/app/wordlists/tech/node_wordlist.txt"),
    "java": Path("/app/wordlists/tech/java_wordlist.txt"),
    "spring": Path("/app/wordlists/tech/java_wordlist.txt"),
    "tomcat": Path("/app/wordlists/tech/java_wordlist.txt"),
    "aspnet": Path("/app/wordlists/tech/aspnet_wordlist.txt"),
    "api": Path("/app/wordlists/tech/api_wordlist.txt"),
}
BUNDLED_SUBDOMAIN_WORDLISTS = (
    ("use_subdomains_top1million_110000", "puredns-top1m-110k", WORDLIST_DIR / "subdomain" / "subdomains-top1million-110000.txt"),
    ("use_bug_bounty_subdomains_trickest", "puredns-trickest", WORDLIST_DIR / "subdomain" / "bug-bounty-program-subdomains-trickest-inventory.txt"),
)

JS_SECRET_PATTERNS = [
    ("secret", "high", "AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret", "high", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
    ("secret", "high", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("secret", "high", "JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("secret", "medium", "Private key marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("secret", "medium", "Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]")),
]
JS_ENDPOINT_PATTERN = re.compile(r"['\"]((?:https?:)?//[^'\"\s)]+|/(?:api|graphql|v[0-9]|admin|auth|oauth|sso|internal|private|service|rest|wp-json)[^'\"\s)]*)['\"]", re.I)
JS_SOURCE_PATTERNS = [
    ("location.search", re.compile(r"\blocation\.search\b")),
    ("location.hash", re.compile(r"\blocation\.hash\b")),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\s*\(")),
    ("document.cookie", re.compile(r"\bdocument\.cookie\b")),
    ("localStorage", re.compile(r"\blocalStorage\b")),
    ("sessionStorage", re.compile(r"\bsessionStorage\b")),
    ("postMessage/message", re.compile(r"\bpostMessage\b|\baddEventListener\s*\(\s*['\"]message['\"]")),
]
JS_SINK_PATTERNS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=")),
    ("insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function constructor", re.compile(r"\bnew\s+Function\s*\(")),
    ("setTimeout string", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]")),
    ("navigation assignment", re.compile(r"\blocation(?:\.href)?\s*=")),
]


class ScanStopped(RuntimeError):
    """Raised when a user-requested stop should halt the scan cleanly."""


def clean_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("http://").removeprefix("https://").split('/')[0]


def is_subdomain_of(name: str, domain: str) -> bool:
    name = name.strip().lower().rstrip('.')
    domain = domain.strip().lower().rstrip('.')
    return name == domain or name.endswith("." + domain)


def set_scan(db: Session, scan: models.Scan, stage: str, progress: int, status: str = "running", error: str | None = None) -> None:
    scan.stage = stage
    scan.progress = progress
    scan.status = status
    if error:
        scan.error = error
    db.commit()


def ensure_scan_not_stopped(db: Session, scan: models.Scan) -> None:
    db.refresh(scan)
    if scan.status in {"stopping", "stopped"}:
        raise ScanStopped("Scan stopped by user")


def raw_path(scan_id: int, stage: str, tool: str, suffix: str = "txt") -> Path:
    path = RAW_DIR / f"scan-{scan_id}" / stage / f"{tool}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def record_raw(db: Session, scan_id: int, stage: str, tool: str, path: Path) -> None:
    db.add(models.RawOutput(scan_id=scan_id, stage=stage, tool=tool, path=str(path)))
    db.commit()


def record_stage_meta(db: Session, scan_id: int, stage: str, tool: str, data: dict) -> Path:
    path = raw_path(scan_id, stage, tool, "json")
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    record_raw(db, scan_id, stage, tool, path)
    return path


def clear_scan_raw(db: Session, scan_id: int, stage_only: str | None = None) -> None:
    scan_dir = RAW_DIR / f"scan-{scan_id}"
    if stage_only:
        shutil.rmtree(scan_dir / stage_only, ignore_errors=True)
        db.query(models.RawOutput).filter_by(scan_id=scan_id, stage=stage_only).delete()
    else:
        shutil.rmtree(scan_dir, ignore_errors=True)
        db.query(models.RawOutput).filter_by(scan_id=scan_id).delete()
    scan_dir.mkdir(parents=True, exist_ok=True)
    db.commit()


def _command_for_scan(scan_id: int) -> Callable[[list[str], Path | None, int | None], tuple[str, str]]:
    if run_command is not _run_command:
        return run_command
    return CommandRunner(scan_id).run


def _call_command(command: Callable, cmd: list[str], timeout: int | None = None, cwd: Path | None = None) -> tuple[str, str]:
    if cwd is None:
        return command(cmd, timeout=timeout)
    return command(cmd, cwd=cwd, timeout=timeout)


def response_signature(item: dict) -> tuple:
    return (
        item.get("status_code"), item.get("size"), item.get("words"), item.get("lines"),
        (item.get("title") or "").strip().lower(), item.get("redirect_location"), item.get("body_hash"),
    )


def _response_fingerprint_payload(item: dict) -> dict:
    headers = item.get("response_headers") or {}
    stable_headers = {
        str(key).lower(): str(value)
        for key, value in headers.items()
        if str(key).lower() not in {"date", "expires", "set-cookie", "x-request-id", "x-correlation-id", "traceparent"}
    }
    return {
        "status_code": item.get("status_code"),
        "size": item.get("size") if item.get("size") is not None else item.get("response_size"),
        "words": item.get("words"),
        "lines": item.get("lines"),
        "title": (item.get("title") or "").strip() or None,
        "redirect_location": item.get("redirect_location") or item.get("final_url"),
        "body_hash": item.get("body_hash"),
        "headers_hash": stable_fingerprint(stable_headers) if stable_headers else None,
        "content_type": item.get("content_type") or stable_headers.get("content-type"),
        "certificate_fingerprint": item.get("certificate_fingerprint"),
    }


def get_or_create_response_fingerprint(db: Session, item: dict, cache: dict[str, int]) -> int:
    payload = _response_fingerprint_payload(item)
    key = stable_fingerprint(payload)
    if key in cache:
        return cache[key]
    existing = db.query(models.ResponseFingerprint).filter_by(fingerprint_key=key).first()
    if existing:
        cache[key] = existing.id
        return existing.id
    fingerprint = models.ResponseFingerprint(fingerprint_key=key, **payload)
    db.add(fingerprint)
    db.flush()
    cache[key] = fingerprint.id
    return fingerprint.id


def noise_score(item: dict, *, duplicate_count: int = 1, kind: str = "response") -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if duplicate_count > 1:
        score += min(35, 5 + duplicate_count)
        reasons.append(f"{duplicate_count} equivalent observations")
    if item.get("confidence") == "filtered":
        score += 50
        reasons.append("wildcard-like response")
    haystack = " ".join(str(value or "") for value in (
        item.get("title"), item.get("evidence"), item.get("filtered_reason"),
    )).lower()
    if re.search(r"access denied|request blocked|captcha|checking your browser|cloudflare|akamai.*reference", haystack):
        score += 25
        reasons.append("generic WAF or bot response")
    candidate_url = item.get("url") or item.get("source_url") or item.get("indicator")
    if is_static_or_marketing_url(candidate_url):
        score += 25 if kind == "js" else 15
        reasons.append("static or marketing asset")
    return min(100, score), reasons


def novelty_score(*, is_new_identity: bool, new_fingerprint: bool = False, new_attributes: list[str] | None = None) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    if is_new_identity:
        score += 50
        reasons.append("new identity")
    if new_fingerprint:
        score += 25
        reasons.append("new response fingerprint")
    for attribute in new_attributes or []:
        score += 10
        reasons.append(f"new {attribute}")
    return min(100, score), reasons


def probe_random_paths(base_url: str, count: int = 3, headers: dict[str, str] | None = None, proxy: str | None = None, timeout: int = 10) -> list[dict]:
    rows: list[dict] = []
    for _ in range(count):
        path = f"/__ffuf_baseline_{secrets.token_hex(8)}"
        url = base_url.rstrip("/") + path
        try:
            response = pyhttpx.get(url, headers=headers or {}, proxy=proxy, follow_redirects=False, timeout=timeout)
            body = response.content or b""
            text = body.decode(response.encoding or "utf-8", errors="ignore")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            rows.append({
                "url": url, "path": path, "status_code": response.status_code,
                "size": len(body), "words": len(text.split()), "lines": len(text.splitlines()),
                "content_type": response.headers.get("content-type"),
                "redirect_location": response.headers.get("location"),
                "body_hash": hashlib.sha256(body).hexdigest(),
                "body_sample": re.sub(r"\s+", " ", text).strip()[:4096],
                "title": re.sub(r"\s+", " ", title_match.group(1)).strip()[:512] if title_match else None,
            })
        except Exception as exc:
            rows.append({"url": url, "path": path, "error": str(exc)})
    return rows


def derive_ffuf_filters(baseline: list[dict]) -> dict[str, str]:
    valid = [row for row in baseline if not row.get("error")]
    if len(valid) < 2:
        return {}
    keys = ["status_code", "size", "words", "lines", "title", "redirect_location", "body_hash"]
    if not all(tuple(row.get(k) for k in keys) == tuple(valid[0].get(k) for k in keys) for row in valid[1:]):
        return {}
    filters: dict[str, str] = {}
    if valid[0].get("size") is not None:
        filters["filter_size"] = str(valid[0]["size"])
    if valid[0].get("words") is not None:
        filters["filter_words"] = str(valid[0]["words"])
    if valid[0].get("lines") is not None:
        filters["filter_lines"] = str(valid[0]["lines"])
    return filters


def classify_ffuf_result(result: dict, baseline: list[dict]) -> dict:
    classified = dict(result)
    valid = [row for row in baseline if not row.get("error")]
    result_tuple = (
        result.get("status_code"), result.get("size"), result.get("words"), result.get("lines"),
        (result.get("title") or "").strip().lower(), result.get("redirect_location"),
    )
    baseline_tuples = {
        (
            row.get("status_code"), row.get("size"), row.get("words"), row.get("lines"),
            (row.get("title") or "").strip().lower(), row.get("redirect_location"),
        )
        for row in valid
    }
    body_sample = result.get("body_sample")
    body_similarity = max(
        (
            SequenceMatcher(None, body_sample, row.get("body_sample") or "").ratio()
            for row in valid if body_sample and row.get("body_sample")
        ),
        default=0.0,
    )
    if result_tuple in baseline_tuples or body_similarity >= 0.92:
        classified["confidence"] = "filtered"
        classified["filtered_reason"] = "matches wildcard baseline response" if result_tuple in baseline_tuples else f"body is {body_similarity:.0%} similar to wildcard baseline"
    elif result.get("status_code") in {200, 201, 204, 301, 302, 307, 308}:
        classified["confidence"] = "confirmed"
        classified["filtered_reason"] = None
    elif result.get("status_code") in {401, 403}:
        classified["confidence"] = "possible"
        classified["filtered_reason"] = None
    else:
        classified["confidence"] = "unverified"
        classified["filtered_reason"] = None
    return classified


def _valid_hostname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    if not re.fullmatch(r"[a-z0-9._-]+", name):
        return False
    labels = name.split(".")
    return not any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)


@dataclass(frozen=True)
class SubdomainDiscovery:
    name: str
    source: str
    depth: int


@dataclass(frozen=True)
class SubdomainBruteforceWordlist:
    path: Path
    source: str


@dataclass(frozen=True)
class EnumToolResult:
    tool: str
    out: Path
    ok: bool
    error: str | None = None


@dataclass(frozen=True)
class FfufHostContext:
    scan_id: int
    url: str
    config: dict
    headers: dict[str, str]
    proxy: str | None
    wordlist_path: Path
    fingerprints: list[str]


@dataclass(frozen=True)
class FfufHostResult:
    url: str
    out: Path
    baseline_out: Path | None = None
    items: list[dict] | None = None
    error: dict | None = None


def _read_wordlist_lines(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(errors="ignore").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (FileNotFoundError, OSError):
        return []


def build_ffuf_wordlist_for_host(scan_id: int, url: str, fingerprints: list[str], generic_wordlist: Path | None, mode: str) -> Path:
    if mode == "generic" and generic_wordlist:
        return generic_wordlist
    paths: list[Path] = []
    for fingerprint in fingerprints or ["unknown"]:
        path = BUNDLED_TECH_WORDLISTS.get(fingerprint.lower())
        if path and path not in paths:
            paths.append(path)
    if not paths:
        paths.append(Path("/app/wordlists/tech/api_wordlist.txt"))
    lines: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for line in _read_wordlist_lines(path):
            if line not in seen:
                seen.add(line)
                lines.append(line)
    if mode == "combined" and generic_wordlist:
        for line in _read_wordlist_lines(generic_wordlist):
            if line not in seen:
                seen.add(line)
                lines.append(line)
    if not lines and generic_wordlist:
        return generic_wordlist
    safe_url = re.sub(r"[^a-zA-Z0-9_.-]", "_", url)
    out = raw_path(scan_id, "ffuf-wordlists", safe_url)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _normalize_discoveries(discoveries: Sequence[SubdomainDiscovery]) -> dict[str, tuple[set[str], set[int]]]:
    normalized: dict[str, tuple[set[str], set[int]]] = {}
    for item in discoveries:
        name = item.name.strip().lower().rstrip(".")
        if not _valid_hostname(name):
            continue
        sources, depths = normalized.setdefault(name, (set(), set()))
        sources.add(item.source)
        depths.add(item.depth)
    return normalized


def batch_upsert_subdomains(db: Session, target_id: int, scan_id: int, discoveries: Sequence[SubdomainDiscovery | tuple[str, str, int]]) -> None:
    normalized = _normalize_discoveries([
        item if isinstance(item, SubdomainDiscovery) else SubdomainDiscovery(*item)
        for item in discoveries
    ])
    if not normalized:
        return

    existing = {
        row.name: row
        for row in db.query(models.Subdomain).filter(models.Subdomain.target_id == target_id, models.Subdomain.name.in_(normalized.keys())).all()
    }
    to_add = []
    for name, (sources, depths) in normalized.items():
        row = existing.get(name)
        if row:
            row.scan_id = scan_id
            row.sources = sorted(set(row.sources or []) | sources)
            row.depths = sorted(set(row.depths or []) | depths)
        else:
            row = models.Subdomain(
                target_id=target_id,
                scan_id=scan_id,
                name=name,
                sources=sorted(sources),
                depths=sorted(depths),
                first_seen_scan_id=scan_id,
            )
            existing[name] = row
            to_add.append(row)
    for obj in to_add:
        db.add(obj)
    db.flush()


def upsert_subdomain(db: Session, target_id: int, scan_id: int, name: str, source: str, depth: int) -> None:
    batch_upsert_subdomains(db, target_id, scan_id, [SubdomainDiscovery(name, source, depth)])


def crtsh(domain: str) -> set[str]:
    try:
        r = pyhttpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        r.raise_for_status()
        out: set[str] = set()
        for item in r.json():
            for name in str(item.get("name_value", "")).splitlines():
                name = name.replace("*.", "").strip().lower()
                if is_subdomain_of(name, domain):
                    out.add(name)
        return out
    except Exception as e:
        logger.warning("crtsh: certificate transparency query failed for %s — %s", domain, str(e)[:80])
        return set()


def mutate_names(names: set[str], domain: str) -> set[str]:
    words = ["dev", "stage", "staging", "test", "uat", "prod", "admin", "api", "internal"]
    out: set[str] = set()
    for name in names:
        if not is_subdomain_of(name, domain):
            continue
        left = name[: -(len(domain) + 1)] if name != domain else ""
        first = left.split('.')[0] if left else ""
        if not first:
            continue
        for w in words:
            out.add(f"{first}-{w}.{domain}")
            out.add(f"{w}-{first}.{domain}")
            out.add(f"{w}.{name}")
    return out


def _parse_new_names(out: Path, seen: set[str]) -> list[str]:
    names: list[str] = []
    try:
        for line in out.read_text(errors="ignore").splitlines():
            name = line.strip().lower().rstrip(".")
            if not name or name in seen or not _valid_hostname(name):
                continue
            seen.add(name)
            names.append(name)
    except (FileNotFoundError, OSError):
        pass
    return names


def _run_enum_tool(tool: str, builder, domain: str, out: Path, timeout: int, command: Callable) -> EnumToolResult:
    try:
        _call_command(command, builder(domain, out), timeout=timeout)
        return EnumToolResult(tool, out, True)
    except Exception as e:
        out.write_text(str(e))
        return EnumToolResult(tool, out, False, str(e))


def _run_crtsh(domain: str, out: Path) -> EnumToolResult:
    result = crtsh(domain)
    out.write_text("\n".join(sorted(result)))
    return EnumToolResult("crtsh", out, True)


def _persist_enum_result(db: Session, scan: models.Scan, source: str, result: EnumToolResult, seen: set[str], depth: int = 0) -> list[str]:
    if not result.ok:
        record_raw(db, scan.id, "subdomains", f"{result.tool}-error", result.out)
        return []
    names = _parse_new_names(result.out, seen)
    record_raw(db, scan.id, "subdomains", result.tool, result.out)
    for start in range(0, len(names), 100):
        batch = names[start:start + 100]
        batch_upsert_subdomains(db, scan.target_id, scan.id, [SubdomainDiscovery(name, source, depth) for name in batch])
        db.commit()
    return names


def _subdomain_bruteforce_wordlists(db: Session, config: dict) -> list[SubdomainBruteforceWordlist]:
    wordlists: list[SubdomainBruteforceWordlist] = []
    selected = db.get(models.Wordlist, config.get("subdomain_wordlist_id")) if config.get("subdomain_wordlist_id") else None
    if selected:
        wordlists.append(SubdomainBruteforceWordlist(Path(selected.path), "puredns"))
    for flag, source, path in BUNDLED_SUBDOMAIN_WORDLISTS:
        if config.get(flag, False):
            wordlists.append(SubdomainBruteforceWordlist(path, source))
    return wordlists


def cached_subdomain_names(db: Session, target_id: int) -> list[str]:
    return [
        row.name
        for row in db.query(models.Subdomain.name)
        .filter_by(target_id=target_id)
        .order_by(models.Subdomain.name)
        .all()
    ]


def scan_subdomain_names(db: Session, scan: models.Scan) -> list[str]:
    config = scan.config or {}
    query = db.query(models.Subdomain.name).filter_by(target_id=scan.target_id)
    if config.get("fresh_subdomain_scan", False) or not config.get("use_cached_subdomains", True):
        query = query.filter(or_(models.Subdomain.scan_id == scan.id, models.Subdomain.first_seen_scan_id == scan.id))
    return [row.name for row in query.order_by(models.Subdomain.name).all()]


def enumerate_subdomains(db: Session, scan: models.Scan) -> list[str]:
    config = scan.config or {}
    target = scan.target
    domain = target.domain
    brute_wordlists = _subdomain_bruteforce_wordlists(db, config)
    depth_max = int(config.get("recursion_depth", 2))
    subfinder_timeout = int(config.get("subfinder_timeout", 300))
    amass_timeout = int(config.get("amass_timeout", 600))
    command = _command_for_scan(scan.id)
    use_cache = bool(config.get("use_cached_subdomains", True))
    fresh_only = bool(config.get("fresh_subdomain_scan", False))
    refresh_passive = bool(config.get("refresh_passive_subdomains", True))
    use_crtsh = bool(config.get("use_crtsh", False))
    cached_names = [] if fresh_only or not use_cache else cached_subdomain_names(db, target.id)
    seen: set[str] = {domain, *cached_names}
    batch_upsert_subdomains(db, target.id, scan.id, [SubdomainDiscovery(domain, "root", 0)])
    if cached_names:
        cache_out = raw_path(scan.id, "subdomains", "cache")
        cache_out.write_text("\n".join(cached_names), encoding="utf-8")
        record_raw(db, scan.id, "subdomains", "cache", cache_out)
    db.commit()

    if refresh_passive:
        subfinder_out = raw_path(scan.id, "subdomains", "subfinder")
        with ThreadPoolExecutor(max_workers=SCAN_CONCURRENT_ENUM) as exc:
            futures = [
                exc.submit(
                    _run_enum_tool,
                    "subfinder",
                    lambda d, o: build_subfinder_command(d, o, bool(config.get("subfinder_recursive", False))),
                    domain,
                    subfinder_out,
                    subfinder_timeout,
                    command,
                ),
            ]
            if use_crtsh:
                crtsh_out = raw_path(scan.id, "subdomains", "crtsh")
                futures.append(exc.submit(_run_crtsh, domain, crtsh_out))
            if config.get("run_amass", False):
                amass_out = raw_path(scan.id, "subdomains", "amass")
                futures.append(exc.submit(_run_enum_tool, "amass", build_amass_command, domain, amass_out, amass_timeout, command))
            for future in as_completed(futures):
                result = future.result()
                _persist_enum_result(db, scan, result.tool, result, seen)
    else:
        skipped_out = raw_path(scan.id, "subdomains", "passive-skipped")
        skipped_out.write_text("Passive subdomain refresh skipped by scan settings.\n", encoding="utf-8")
        record_raw(db, scan.id, "subdomains", "passive-skipped", skipped_out)

    frontier: set[str] = set(seen) or {domain}
    if brute_wordlists:
        if not DEFAULT_RESOLVERS.exists():
            DEFAULT_RESOLVERS.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n")
        for depth in range(1, depth_max + 1):
            next_frontier: set[str] = set()
            for base in sorted(frontier):
                safe_base = re.sub(r"[^a-zA-Z0-9_.-]", "_", base)
                for brute_wordlist in brute_wordlists:
                    out = raw_path(scan.id, f"subdomains-depth-{depth}", f"{brute_wordlist.source}-{safe_base}")
                    try:
                        if not brute_wordlist.path.exists():
                            raise FileNotFoundError(f"Subdomain wordlist not found: {brute_wordlist.path}")
                        _call_command(command, build_puredns_command(base, brute_wordlist.path, DEFAULT_RESOLVERS, out), timeout=1800)
                        names = _parse_new_names(out, seen)
                        record_raw(db, scan.id, f"subdomains-depth-{depth}", brute_wordlist.source, out)
                        if names:
                            for start in range(0, len(names), 100):
                                batch = names[start:start + 100]
                                batch_upsert_subdomains(db, target.id, scan.id, [SubdomainDiscovery(name, brute_wordlist.source, depth) for name in batch])
                                db.commit()
                            next_frontier.update(names)
                    except Exception as e:
                        out.write_text(str(e))
                        record_raw(db, scan.id, f"subdomains-depth-{depth}", f"{brute_wordlist.source}-error", out)
            mutations = [SubdomainDiscovery(name, "mutation", depth) for name in mutate_names(next_frontier or frontier, domain) if name not in seen]
            for item in mutations:
                seen.add(item.name)
            if mutations:
                for start in range(0, len(mutations), 100):
                    batch_upsert_subdomains(db, target.id, scan.id, mutations[start:start + 100])
                    db.commit()
            frontier = next_frontier
            db.commit()
    db.commit()
    return sorted(seen)


def run_naabu(db: Session, scan: models.Scan) -> list[dict]:
    command = _command_for_scan(scan.id)
    hosts = scan_subdomain_names(db, scan)
    infile = raw_path(scan.id, "naabu", "input")
    outfile = raw_path(scan.id, "naabu", "naabu", "jsonl")
    infile.write_text("\n".join(sorted(set(hosts))))
    if not hosts:
        outfile.write_text("")
        record_raw(db, scan.id, "naabu", "naabu", outfile)
        return []
    try:
        _call_command(command, build_naabu_command(infile, outfile, str((scan.config or {}).get("naabu_ports", "")) or None), timeout=int((scan.config or {}).get("naabu_timeout", 1800)))
    except Exception as exc:
        err = raw_path(scan.id, "naabu", "naabu-error")
        err.write_text(str(exc), encoding="utf-8")
        record_raw(db, scan.id, "naabu", "naabu-error", err)
        return []
    if not outfile.exists():
        outfile.write_text("")
    record_raw(db, scan.id, "naabu", "naabu", outfile)
    rows = parse_naabu_jsonl(outfile.read_text(errors="ignore"))
    existing = {(r.host, r.port, r.protocol) for r in db.query(models.PortResult).filter_by(scan_id=scan.id).all()}
    prior_cache: dict[tuple[str, int, str], int] = {}
    for item in rows:
        key = (item["host"], item["port"], item.get("protocol") or "tcp")
        if key in existing:
            continue
        prior_key = key
        if prior_key not in prior_cache:
            prior = db.query(models.PortResult).filter_by(target_id=scan.target_id, host=key[0], port=key[1], protocol=key[2]).order_by(models.PortResult.id.asc()).first()
            prior_cache[prior_key] = prior.first_seen_scan_id if prior else scan.id
        db.add(models.PortResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_cache[prior_key], source="naabu", **item))
    db.commit()
    return rows


def probe_candidate_response(url: str, headers: dict[str, str] | None = None, proxy: str | None = None, timeout: int = 10) -> dict:
    response = pyhttpx.get(url, headers=headers or {}, proxy=proxy, follow_redirects=False, timeout=timeout)
    body = response.content or b""
    text = body.decode(response.encoding or "utf-8", errors="ignore")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return {
        "status_code": response.status_code,
        "size": len(body),
        "words": len(text.split()),
        "lines": len(text.splitlines()),
        "content_type": response.headers.get("content-type"),
        "redirect_location": response.headers.get("location"),
        "body_hash": hashlib.sha256(body).hexdigest(),
        "body_sample": re.sub(r"\s+", " ", text).strip()[:4096],
        "title": re.sub(r"\s+", " ", title_match.group(1)).strip()[:512] if title_match else None,
    }


def _near_wildcard_baseline(result: dict, baseline: list[dict]) -> bool:
    for row in baseline:
        if row.get("error") or result.get("status_code") != row.get("status_code"):
            continue
        size = result.get("size")
        baseline_size = row.get("size")
        words = result.get("words")
        baseline_words = row.get("words")
        size_close = size is not None and baseline_size is not None and abs(size - baseline_size) <= max(32, int(max(size, baseline_size) * 0.05))
        words_close = words is not None and baseline_words is not None and abs(words - baseline_words) <= max(3, int(max(words, baseline_words) * 0.08))
        if size_close or words_close:
            return True
    return False


def _host_from_url(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower()


def _httpx_inputs_from_ports(subdomains: list[str], ports: list[dict]) -> list[str]:
    inputs = set(subdomains)
    for item in ports:
        port = int(item.get("port") or 0)
        host = item.get("host")
        if host and port in WEB_PORTS:
            inputs.add(f"{host}:{port}")
    return sorted(inputs)


def fetch_response_headers(url: str, settings, timeout: int = 10) -> dict:
    try:
        response = pyhttpx.get(url, headers=settings.headers or {}, proxy=settings.proxy, follow_redirects=False, timeout=timeout)
        return {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        return {}


def fingerprint_host(item: dict, response_headers: dict, ports: list[int]) -> list[str]:
    haystack = " ".join([
        item.get("url") or "",
        item.get("title") or "",
        item.get("server") or "",
        " ".join(item.get("tech") or []),
        " ".join(f"{k}: {v}" for k, v in (response_headers or {}).items()),
    ]).lower()
    tags: set[str] = set()
    rules = [
        ("wordpress", r"wordpress|wp-content|wp-json|wp-includes"),
        ("php", r"\bphp\b|x-powered-by:\s*php|laravel|symfony|codeigniter"),
        ("node", r"node\.js|express|next\.js|nuxt|x-powered-by:\s*express"),
        ("graphql", r"graphql|apollo"),
        ("java", r"\bjava\b|spring|tomcat|jetty|jboss|struts|jsessionid"),
        ("aspnet", r"asp\.net|iis|x-aspnet|x-powered-by:\s*asp"),
        ("api", r"\bapi\b|swagger|openapi|rest|json"),
    ]
    for tag, pattern in rules:
        if re.search(pattern, haystack):
            tags.add(tag)
    if any(port in ports for port in [8080, 8081, 8443, 9000, 9443]):
        tags.add("java")
    if any(port in ports for port in [3000, 3001, 5000, 5173]):
        tags.add("node")
    if not tags:
        tags.add("unknown")
    return sorted(tags)


def merge_fingerprints(tech: list[str], existing: list[str] | None = None) -> list[str]:
    item = {"url": "", "title": "", "server": "", "tech": tech}
    merged = set(existing or [])
    merged.update(fingerprint_host(item, {}, []))
    if len(merged) > 1 and "unknown" in merged:
        merged.remove("unknown")
    return sorted(merged)


def run_httpx(db: Session, scan: models.Scan) -> list[str]:
    settings = load_settings()
    command = _command_for_scan(scan.id)
    subs = scan_subdomain_names(db, scan)
    port_rows = [r for r in db.query(models.PortResult).filter_by(scan_id=scan.id).all()]
    host_ports: dict[str, list[int]] = {}
    for row in port_rows:
        host_ports.setdefault(row.host, []).append(row.port)
    inputs = _httpx_inputs_from_ports(subs, [{"host": r.host, "port": r.port} for r in port_rows])
    infile = raw_path(scan.id, "httpx", "input")
    outfile = raw_path(scan.id, "httpx", "httpx", "jsonl")
    outfile.parent.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(inputs))
    if not inputs:
        outfile.write_text("")
        record_raw(db, scan.id, "httpx", "httpx", outfile)
        return []
    headers = settings.headers.copy()
    try:
        _call_command(command, build_httpx_command(infile, outfile, settings.user_agent, headers, settings.proxy), timeout=1800)
    except Exception as exc:
        err = raw_path(scan.id, "httpx", "httpx-error")
        err.write_text(str(exc), encoding="utf-8")
        record_raw(db, scan.id, "httpx", "httpx-error", err)
        raise
    if not outfile.exists():
        outfile.write_text("")
    record_raw(db, scan.id, "httpx", "httpx", outfile)
    rows = parse_httpx_jsonl(outfile.read_text(errors="ignore"))
    grouped: dict[str, dict] = {}
    for item in rows:
        if not item.get("url"):
            continue
        asset_key = item.get("asset_key") or canonical_asset_key(item["url"])
        item["asset_key"] = asset_key
        current = grouped.get(asset_key)
        if current is None:
            grouped[asset_key] = item
            continue
        current["variants"] = (current.get("variants") or []) + (item.get("variants") or [])
        current["observation_count"] = len(current["variants"])
        current["ports"] = sorted(set(current.get("ports") or []) | set(item.get("ports") or []))
        current["tech"] = sorted(set(current.get("tech") or []) | set(item.get("tech") or []))
        current["redirect_hops"] = current.get("redirect_hops") or item.get("redirect_hops") or []
        current["final_url"] = current.get("final_url") or item.get("final_url")
    rows = list(grouped.values())
    urls = []
    existing_assets = {
        r.asset_key or canonical_asset_key(r.url)
        for r in db.query(models.HttpxResult).filter_by(scan_id=scan.id).all()
    }
    prior_rows = db.query(models.HttpxResult).filter(models.HttpxResult.target_id == scan.target_id, models.HttpxResult.scan_id != scan.id).all()
    prior_assets = {r.asset_key or canonical_asset_key(r.url) for r in prior_rows}
    prior_fingerprint_ids = {r.fingerprint_id for r in prior_rows if r.fingerprint_id}
    prior_tech = {tech for r in prior_rows for tech in (r.tech or [])}
    prior_statuses = {r.status_code for r in prior_rows if r.status_code is not None}
    prior_certificates = {r.certificate_fingerprint for r in prior_rows if r.certificate_fingerprint}
    prior_header_names = {str(key).lower() for r in prior_rows for key in (r.response_headers or {})}
    fingerprint_cache: dict[str, int] = {}
    prior_map: dict[str, int] = {}
    to_add = []
    for item in rows:
        if not item.get("url"):
            continue
        url = item["url"]
        host = _host_from_url(url)
        response_headers = fetch_response_headers(url, settings)
        ports = sorted(set(host_ports.get(host, [])))
        item["response_headers"] = response_headers
        item["ports"] = ports
        item["fingerprints"] = fingerprint_host(item, response_headers, ports)
        item["fingerprint_id"] = get_or_create_response_fingerprint(db, item, fingerprint_cache)
        item["observation_count"] = max(1, len(item.get("variants") or []))
        item["noise_score"], item["noise_reasons"] = noise_score(item, duplicate_count=item["observation_count"], kind="http")
        new_attributes = []
        if any(tech not in prior_tech for tech in item.get("tech") or []):
            new_attributes.append("technology")
        if item.get("status_code") not in prior_statuses:
            new_attributes.append("status")
        if any(str(key).lower() not in prior_header_names for key in response_headers):
            new_attributes.append("header")
        if item.get("certificate_fingerprint") and item["certificate_fingerprint"] not in prior_certificates:
            new_attributes.append("certificate")
        item["novelty_score"], item["novelty_reasons"] = novelty_score(
            is_new_identity=item["asset_key"] not in prior_assets,
            new_fingerprint=item["fingerprint_id"] not in prior_fingerprint_ids,
            new_attributes=new_attributes,
        )
        urls.append(url)
        if item["asset_key"] in existing_assets:
            continue
        if item["asset_key"] not in prior_map:
            prior = next((row for row in prior_rows if (row.asset_key or canonical_asset_key(row.url)) == item["asset_key"]), None)
            prior_map[item["asset_key"]] = prior.first_seen_scan_id if prior else scan.id
        to_add.append(models.HttpxResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_map[item["asset_key"]], headers_sent={"User-Agent": settings.user_agent, **headers}, **item))
    for obj in to_add:
        db.add(obj)
    db.commit()
    return urls


def run_wappalyzer(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    scan_type = str(config.get("wappalyzer_scan_type") or "balanced")
    if scan_type not in {"fast", "balanced", "full"}:
        scan_type = "balanced"
    workers = int(config.get("wappalyzer_workers", 5))
    query = db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    if urls:
        query = query.filter(models.HttpxResult.url.in_(urls))
    rows = query.all()
    stats = {"total_hosts": len(rows), "updated_hosts": 0, "failed": False}
    infile = raw_path(scan.id, "wappalyzer", "input")
    outfile = raw_path(scan.id, "wappalyzer", "wappalyzer", "json")
    infile.write_text("\n".join(row.url for row in rows), encoding="utf-8")
    if not rows:
        outfile.write_text("{}", encoding="utf-8")
        record_raw(db, scan.id, "wappalyzer", "wappalyzer", outfile)
        return stats
    command = _command_for_scan(scan.id)
    try:
        _call_command(command, build_wappalyzer_command(infile, outfile, scan_type, workers), timeout=int(config.get("wappalyzer_timeout", 1800)))
    except Exception as exc:
        err = raw_path(scan.id, "wappalyzer", "wappalyzer-error")
        err.write_text(str(exc), encoding="utf-8")
        record_raw(db, scan.id, "wappalyzer", "wappalyzer-error", err)
        stats["failed"] = True
        return stats
    if not outfile.exists():
        outfile.write_text("{}", encoding="utf-8")
    record_raw(db, scan.id, "wappalyzer", "wappalyzer", outfile)
    detected = parse_wappalyzer_json(outfile.read_text(errors="ignore"))
    for row in rows:
        names = detected.get(row.url) or detected.get(row.url.rstrip("/")) or []
        if not names:
            continue
        tech = sorted(set(row.tech or []) | set(names))
        row.tech = tech
        row.fingerprints = merge_fingerprints(tech, row.fingerprints or [])
        stats["updated_hosts"] += 1
    db.commit()
    return stats


def _line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_newline = text.rfind("\n", 0, index)
    col = index + 1 if last_newline < 0 else index - last_newline
    return line, col


def _masked_context(text: str, start: int, end: int, window: int = 90) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    match = text[start:end]
    if len(match) > 12:
        masked = f"{match[:4]}…{match[-4:]}"
    else:
        masked = "…"
    return (text[left:start] + masked + text[end:right]).replace("\n", " ")[:260]


def _script_urls_from_html(html: str, base_url: str) -> list[str]:
    urls: set[str] = set()
    for match in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", html, re.I):
        src = (match.group(1) or "").strip()
        if src and not src.lower().startswith(("data:", "blob:", "javascript:")):
            urls.add(urljoin(base_url, src))
    return sorted(urls)


def _inline_scripts_from_html(html: str) -> list[str]:
    scripts = []
    for match in re.finditer(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S):
        body = (match.group(1) or "").strip()
        if len(body) >= 40:
            scripts.append(body)
    return scripts


def _is_same_target_url(candidate: str, target_domain: str) -> bool:
    host = _host_from_url(candidate)
    return bool(host and is_subdomain_of(host.split(":")[0], target_domain))


def analyze_js_text(text: str, source_url: str, page_url: str | None, target_domain: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, severity: str, indicator: str, match, tags: list[str], confidence: str = "heuristic", probable: bool = False):
        key = (kind, indicator)
        if key in seen:
            return
        seen.add(key)
        line, col = _line_col(text, match.start() if hasattr(match, "start") else 0)
        findings.append({
            "page_url": page_url,
            "source_url": source_url,
            "finding_type": kind,
            "severity": severity,
            "indicator": indicator[:1024],
            "evidence": _masked_context(text, match.start(), match.end()) if hasattr(match, "start") else None,
            "line": line,
            "column": col,
            "confidence": confidence,
            "classification": "probable_vulnerability" if probable else "interesting_lead",
            "probable_vulnerability": probable,
            "tags": tags,
        })

    for kind, severity, label, pattern in JS_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            add(kind, severity, label, match, ["secret", "review"])

    for match in JS_ENDPOINT_PATTERN.finditer(text):
        endpoint = match.group(1).strip()
        absolute = urljoin(page_url or source_url, endpoint)
        if endpoint.startswith(("http://", "https://", "//")) and not _is_same_target_url(absolute, target_domain):
            continue
        if is_static_or_marketing_url(absolute):
            continue
        api_like = is_api_like_endpoint(absolute)
        severity = "medium" if api_like and re.search(r"/(?:admin|internal|private|oauth|sso|graphql)", endpoint, re.I) else "low"
        add("endpoint", severity, endpoint, match, ["endpoint", "api"] if api_like else ["endpoint", "route"], "pattern")

    if re.search(r"sourceMappingURL=.*\.map", text, re.I) or source_url.endswith(".map"):
        add("sourcemap", "medium", "Source map reference", re.search(r"sourceMappingURL=.*", text, re.I) or re.match(r".*", source_url), ["source-map", "review"], "pattern")

    source_hits = []
    sink_hits = []
    for label, pattern in JS_SOURCE_PATTERNS:
        match = pattern.search(text)
        if match:
            source_hits.append(label)
            add("source", "info", label, match, ["source"])
    for label, pattern in JS_SINK_PATTERNS:
        match = pattern.search(text)
        if match:
            sink_hits.append(label)
            add("sink", "medium" if label in {"eval", "Function constructor", "document.write"} else "low", label, match, ["sink", "dom"])
    if source_hits and sink_hits:
        indicator = f"{source_hits[0]} → {sink_hits[0]}"
        first_source = next(p.search(text) for _, p in JS_SOURCE_PATTERNS if p.search(text))
        add("source-sink", "medium", indicator, first_source, ["source-sink", "xss", "manual-review"], "heuristic")

    return findings


def _fetch_text(url: str, settings, timeout: int, max_bytes: int) -> tuple[str, dict]:
    headers = {"User-Agent": settings.user_agent, **(settings.headers or {})}
    with pyhttpx.Client(headers=headers, proxy=settings.proxy, follow_redirects=True, timeout=timeout) as client:
        with client.stream("GET", url) as response:
            chunks = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    break
                chunks.append(chunk)
            body = b"".join(chunks)
            text = body.decode(response.encoding or "utf-8", errors="ignore")
            return text, {"status_code": response.status_code, "content_type": response.headers.get("content-type"), "bytes": len(body)}


def _safe_trufflehog_results(value: str | None) -> str:
    allowed = {"verified", "unknown", "unverified", "filtered_unverified"}
    selected = [item.strip().lower() for item in str(value or "").split(",") if item.strip()]
    selected = [item for item in selected if item in allowed]
    return ",".join(selected or ["verified", "unknown", "unverified"])


def _trufflehog_source_metadata(item: dict) -> dict:
    data = ((item.get("SourceMetadata") or {}).get("Data") or {})
    for value in data.values():
        if isinstance(value, dict):
            return value
    return {}


def parse_trufflehog_json(text: str, file_to_url: dict[str, dict]) -> list[dict]:
    findings: list[dict] = []
    objects: list[dict] = []
    stripped = (text or "").strip()
    if not stripped:
        return findings
    try:
        parsed = json.loads(stripped)
        objects = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_line = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed_line, dict):
                objects.append(parsed_line)
    for item in objects:
        metadata = _trufflehog_source_metadata(item)
        file_path = metadata.get("file") or metadata.get("File") or item.get("SourceName") or ""
        normalized_file = str(file_path).replace("\\", "/")
        mapped = file_to_url.get(file_path) or file_to_url.get(normalized_file) or {}
        detector = item.get("DetectorName") or item.get("DetectorType") or item.get("Detector") or "Secret"
        verified = bool(item.get("Verified"))
        verification_error = item.get("VerificationError")
        raw_value = item.get("Raw") or item.get("RawV2") or item.get("Redacted") or detector
        redacted = item.get("Redacted") or (f"{str(raw_value)[:4]}…{str(raw_value)[-4:]}" if len(str(raw_value)) > 12 else "redacted")
        if verified:
            severity = "high"
            confidence = "verified"
        elif verification_error:
            severity = "medium"
            confidence = "unknown"
        else:
            severity = "medium"
            confidence = "unverified"
        line = metadata.get("line") or metadata.get("Line") or item.get("Line")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        findings.append({
            "page_url": mapped.get("page_url"),
            "source_url": mapped.get("source_url") or file_path or "trufflehog",
            "file_path": mapped.get("file_path") or file_path or None,
            "finding_type": "trufflehog-secret",
            "severity": severity,
            "indicator": f"{detector}: {redacted}"[:1024],
            "evidence": str(redacted)[:260],
            "line": line,
            "column": None,
            "confidence": confidence,
            "classification": "probable_vulnerability" if verified else "interesting_lead",
            "probable_vulnerability": verified,
            "tags": ["secret", "trufflehog", confidence],
        })
    return findings


def gowitness_stem_candidates(url: str) -> set[str]:
    trimmed = url.rstrip("/")
    candidates = {trimmed, trimmed.replace("://", "_", 1)}
    dashed = trimmed.replace("://", "---", 1)
    candidates.add(dashed)
    candidates.add(dashed.replace(":", "-").replace("/", "-"))
    candidates.add(re.sub(r"[^A-Za-z0-9_.-]+", "-", dashed))
    return {item for item in candidates if item}


def decode_gowitness_stem(stem: str) -> str:
    if "://" in stem:
        return stem
    if "_" in stem:
        return stem.replace("_", "://", 1)
    for scheme in ("https", "http"):
        prefix = f"{scheme}---"
        if stem.startswith(prefix):
            rest = stem[len(prefix):]
            if "-" in rest:
                host_part, possible_port = rest.rsplit("-", 1)
                if possible_port.isdigit():
                    return f"{scheme}://{host_part}:{possible_port}"
            return f"{scheme}://{rest}"
    return stem


def run_js_intel(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    settings = load_settings()
    max_hosts = int(config.get("js_intel_max_hosts", 80))
    max_scripts = int(config.get("js_intel_max_scripts_per_host", 25))
    max_bytes = int(config.get("js_intel_max_bytes", 2_000_000))
    timeout = int(config.get("js_intel_timeout", 180))
    per_request_timeout = max(5, min(20, timeout // max(1, max_hosts)))
    trufflehog_results = _safe_trufflehog_results(config.get("trufflehog_results"))
    trufflehog_concurrency = int(config.get("trufflehog_concurrency", 4))
    query = db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    if urls:
        query = query.filter(models.HttpxResult.url.in_(urls))
    hosts = query.order_by(models.HttpxResult.status_code.asc()).limit(max_hosts).all()
    manifest = {"hosts": len(hosts), "scripts": [], "trufflehog": {}, "errors": []}
    stats = {"hosts": len(hosts), "bundles": 0, "bundle_observations": 0, "duplicate_bundles": 0, "findings": 0, "high": 0, "trufflehog": 0, "failed": False}
    file_to_url: dict[str, dict] = {}
    current_findings = db.query(models.JsFinding).filter_by(scan_id=scan.id).all()
    existing = {
        (r.content_hash or hashlib.sha256((r.source_url or "").encode()).hexdigest(), r.finding_type, r.normalized_indicator or normalize_indicator(r.indicator))
        for r in current_findings
    }
    findings_by_hash: dict[str, list[models.JsFinding]] = {}
    for row in current_findings:
        if row.content_hash:
            findings_by_hash.setdefault(row.content_hash, []).append(row)
    analyzed_hashes = {r.content_hash for r in current_findings if r.content_hash}
    prior_findings = db.query(models.JsFinding).filter(models.JsFinding.target_id == scan.target_id, models.JsFinding.scan_id != scan.id).all()
    prior_hashes = {r.content_hash for r in prior_findings if r.content_hash}
    prior_js_keys = {
        (r.content_hash, r.finding_type, r.normalized_indicator or normalize_indicator(r.indicator))
        for r in prior_findings if r.content_hash
    }
    pending = []
    for host in hosts:
        ensure_scan_not_stopped(db, scan)
        try:
            html, meta = _fetch_text(host.url, settings, per_request_timeout, max_bytes)
        except Exception as exc:
            manifest["errors"].append({"url": host.url, "error": str(exc)})
            continue
        scripts = _script_urls_from_html(html, host.url)[:max_scripts]
        inline_scripts = _inline_scripts_from_html(html)[:3]
        sources = [(script_url, None) for script_url in scripts]
        for idx, script_text in enumerate(inline_scripts, 1):
            sources.append((f"{host.url}#inline-script-{idx}", script_text))
        for script_url, inline_text in sources:
            ensure_scan_not_stopped(db, scan)
            try:
                if inline_text is None:
                    if not _is_same_target_url(script_url, scan.target.domain):
                        continue
                    text, script_meta = _fetch_text(script_url, settings, per_request_timeout, max_bytes)
                else:
                    text, script_meta = inline_text, {"status_code": meta["status_code"], "content_type": "inline-script", "bytes": len(inline_text)}
                content_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
                safe_name = content_hash[:20]
                out = raw_path(scan.id, "js_intel", safe_name, "js")
                variant = {"page_url": host.url, "source_url": script_url}
                stats["bundle_observations"] += 1
                if content_hash in analyzed_hashes:
                    stats["duplicate_bundles"] += 1
                    for stored in findings_by_hash.get(content_hash, []):
                        variants = list(stored.variants or [])
                        if variant not in variants:
                            variants.append(variant)
                            stored.variants = variants
                            stored.observation_count = len(variants)
                            stored.noise_score, stored.noise_reasons = noise_score(
                                {"source_url": stored.source_url},
                                duplicate_count=stored.observation_count,
                                kind="js",
                            )
                    manifest["scripts"].append({"page_url": host.url, "source_url": script_url, "content_hash": content_hash, "duplicate": True, **script_meta})
                    continue
                analyzed_hashes.add(content_hash)
                out.write_text(text, encoding="utf-8", errors="ignore")
                file_to_url[str(out)] = {"page_url": host.url, "source_url": script_url, "file_path": str(out)}
                file_to_url[str(out).replace("\\", "/")] = {"page_url": host.url, "source_url": script_url, "file_path": str(out)}
                stats["bundles"] += 1
                manifest["scripts"].append({"page_url": host.url, "source_url": script_url, "path": str(out), "content_hash": content_hash, "duplicate": False, **script_meta})
                for finding in analyze_js_text(text, script_url, host.url, scan.target.domain):
                    normalized = normalize_indicator(finding["indicator"])
                    key = (content_hash, finding["finding_type"], normalized)
                    if key in existing:
                        continue
                    existing.add(key)
                    if finding["severity"] == "high" and finding.get("probable_vulnerability"):
                        stats["high"] += 1
                    finding["content_hash"] = content_hash
                    finding["normalized_indicator"] = normalized
                    finding["variants"] = [variant]
                    finding["observation_count"] = 1
                    finding["noise_score"], finding["noise_reasons"] = noise_score(finding, kind="js")
                    finding["novelty_score"], finding["novelty_reasons"] = novelty_score(
                        is_new_identity=key not in prior_js_keys,
                        new_fingerprint=content_hash not in prior_hashes,
                    )
                    obj = models.JsFinding(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=scan.id, file_path=str(out), **finding)
                    findings_by_hash.setdefault(content_hash, []).append(obj)
                    pending.append(obj)
                    if len(pending) >= JS_INTEL_BATCH_SIZE:
                        db.add_all(pending)
                        db.commit()
                        stats["findings"] += len(pending)
                        pending = []
            except Exception as exc:
                manifest["errors"].append({"url": script_url, "error": str(exc)})
    bundle_dir = RAW_DIR / f"scan-{scan.id}" / "js_intel"
    trufflehog_out = raw_path(scan.id, "js_intel", "trufflehog", "jsonl")
    trufflehog_err = ""
    if stats["bundles"]:
        ensure_scan_not_stopped(db, scan)
        command = _command_for_scan(scan.id)
        cmd = [
            "trufflehog",
            "filesystem",
            str(bundle_dir),
            "--json",
            f"--results={trufflehog_results}",
            f"--concurrency={max(1, min(32, trufflehog_concurrency))}",
            "--no-update",
        ]
        try:
            stdout, stderr = _call_command(command, cmd, timeout=timeout)
        except CommandError as exc:
            stdout, stderr = exc.stdout or "", exc.stderr or str(exc)
            stats["failed"] = True
        except Exception as exc:
            stdout, stderr = "", str(exc)
            stats["failed"] = True
        trufflehog_out.write_text(stdout or "", encoding="utf-8")
        if stderr:
            trufflehog_err = stderr
            trufflehog_note = raw_path(scan.id, "js_intel", "trufflehog-error" if stats["failed"] else "trufflehog-stderr")
            trufflehog_note.write_text(stderr, encoding="utf-8")
            record_raw(db, scan.id, "js_intel", "trufflehog-error" if stats["failed"] else "trufflehog-stderr", trufflehog_note)
        record_raw(db, scan.id, "js_intel", "trufflehog", trufflehog_out)
        trufflehog_findings = parse_trufflehog_json(stdout or "", file_to_url)
        stats["trufflehog"] = len(trufflehog_findings)
        for finding in trufflehog_findings:
            file_path = finding.get("file_path")
            try:
                content_hash = hashlib.sha256(Path(file_path).read_bytes()).hexdigest() if file_path else hashlib.sha256(finding["source_url"].encode()).hexdigest()
            except OSError:
                content_hash = hashlib.sha256(finding["source_url"].encode()).hexdigest()
            normalized = normalize_indicator(finding["indicator"])
            key = (content_hash, finding["finding_type"], normalized)
            if key in existing:
                continue
            existing.add(key)
            if finding["severity"] == "high" and finding.get("probable_vulnerability"):
                stats["high"] += 1
            file_path = finding.pop("file_path", None)
            finding.update({
                "content_hash": content_hash,
                "normalized_indicator": normalized,
                "variants": [{"page_url": finding.get("page_url"), "source_url": finding["source_url"]}],
                "observation_count": 1,
            })
            finding["noise_score"], finding["noise_reasons"] = noise_score(finding, kind="js")
            finding["novelty_score"], finding["novelty_reasons"] = novelty_score(
                is_new_identity=key not in prior_js_keys,
                new_fingerprint=content_hash not in prior_hashes,
            )
            pending.append(models.JsFinding(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=scan.id, file_path=file_path, **finding))
            if len(pending) >= JS_INTEL_BATCH_SIZE:
                db.add_all(pending)
                db.commit()
                stats["findings"] += len(pending)
                pending = []
    if pending:
        db.add_all(pending)
        db.commit()
        stats["findings"] += len(pending)
    manifest["trufflehog"] = {"results": trufflehog_results, "concurrency": trufflehog_concurrency, "findings": stats["trufflehog"], "error": trufflehog_err[:1000] if trufflehog_err else ""}
    manifest_out = raw_path(scan.id, "js_intel", "manifest", "json")
    manifest_out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    record_raw(db, scan.id, "js_intel", "js-intel-manifest", manifest_out)
    return stats


def _nuclei_input_urls(db: Session, scan: models.Scan, urls: list[str] | None = None) -> list[str]:
    config = scan.config or {}
    max_urls = int(config.get("nuclei_max_urls", 25))
    include_content_paths = bool(config.get("nuclei_include_content_paths", False))
    ordered: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        if not value:
            return
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            return
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return
        seen.add(normalized)
        ordered.append(normalized)

    if urls:
        for url in urls:
            add(url)
        return ordered[:max_urls]

    http_query = db.query(models.HttpxResult.url).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    for row in http_query.order_by(models.HttpxResult.status_code.asc()).all():
        add(row.url)

    if include_content_paths:
        dir_query = db.query(models.DirbResult.url).filter(
            models.DirbResult.scan_id == scan.id,
            models.DirbResult.confidence.in_(["confirmed", "possible"]),
        )
        for row in dir_query.order_by(models.DirbResult.status_code.asc()).all():
            add(row.url)
            if len(ordered) >= max_urls:
                break

    return ordered[:max_urls]


def run_nuclei(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    profile = str(config.get("nuclei_profile") or "light").lower()
    profile_defaults = {
        "light": {"nuclei_severity": "high,critical", "nuclei_tags": "exposure,takeover", "nuclei_types": "http", "nuclei_max_urls": 25, "nuclei_concurrency": 10, "nuclei_rate_limit": 25, "nuclei_timeout": 4, "nuclei_retries": 0, "nuclei_stage_timeout": 300, "nuclei_exclude_tags": "dos,fuzz,intrusive,brute-force,bruteforce,slow", "nuclei_no_interactsh": True, "nuclei_include_content_paths": False},
        "balanced": {"nuclei_severity": "medium,high,critical", "nuclei_tags": "", "nuclei_types": "http,ssl", "nuclei_max_urls": 100, "nuclei_concurrency": 15, "nuclei_rate_limit": 30, "nuclei_timeout": 5, "nuclei_retries": 0, "nuclei_stage_timeout": 900, "nuclei_exclude_tags": "dos,fuzz,intrusive,brute-force,bruteforce,slow", "nuclei_no_interactsh": True, "nuclei_include_content_paths": True},
        "full": {"nuclei_severity": "medium,high,critical", "nuclei_tags": "", "nuclei_types": "", "nuclei_max_urls": 500, "nuclei_concurrency": 20, "nuclei_rate_limit": 30, "nuclei_timeout": 5, "nuclei_retries": 1, "nuclei_stage_timeout": 1800, "nuclei_exclude_tags": "", "nuclei_no_interactsh": False, "nuclei_include_content_paths": True},
    }.get(profile, {})
    for key, value in profile_defaults.items():
        if key not in config or config.get(key) in (None, ""):
            config[key] = value
    input_urls = _nuclei_input_urls(db, scan, urls)
    infile = raw_path(scan.id, "nuclei", "input")
    outfile = raw_path(scan.id, "nuclei", "nuclei", "jsonl")
    infile.write_text("\n".join(input_urls), encoding="utf-8")
    stats = {"input_urls": len(input_urls), "findings": 0, "medium": 0, "high": 0, "critical": 0}
    if not input_urls:
        outfile.write_text("", encoding="utf-8")
        record_raw(db, scan.id, "nuclei", "nuclei-input", infile)
        record_raw(db, scan.id, "nuclei", "nuclei", outfile)
        return stats

    runner: CommandRunner | None = None
    if run_command is _run_command:
        runner = CommandRunner(scan.id)
        command = runner.run
    else:
        command = run_command
    cmd = build_nuclei_command(
        infile,
        outfile,
        str(config.get("nuclei_severity") or "high,critical"),
        int(config.get("nuclei_concurrency", 10)),
        int(config.get("nuclei_rate_limit", 25)),
        int(config.get("nuclei_timeout", 4)),
        int(config.get("nuclei_retries", 0)),
        True,
        Path(os.getenv("NUCLEI_TEMPLATES_DIR", "/root/nuclei-templates")),
        int(config.get("nuclei_stats_interval", 10)),
        str(config.get("nuclei_tags") or ""),
        str(config.get("nuclei_exclude_tags") or ""),
        str(config.get("nuclei_templates") or ""),
        bool(config.get("nuclei_no_interactsh", True)),
        str(config.get("nuclei_types") or ""),
    )
    log_out = raw_path(scan.id, "nuclei", "nuclei-log")
    log_out.write_text(f"Running: {' '.join(cmd)}\n", encoding="utf-8")
    record_raw(db, scan.id, "nuclei", "nuclei-log", log_out)
    stage_timeout = int(config.get("nuclei_stage_timeout", 900))
    timed_out = False
    try:
        if runner:
            stdout, stderr = runner.run_stream(
                cmd,
                timeout=stage_timeout,
                output_path=log_out,
                log_prefix=f"[scan {scan.id} nuclei] ",
            )
        else:
            stdout, stderr = _call_command(command, cmd, timeout=stage_timeout)
    except CommandError as exc:
        stdout, stderr = exc.stdout or "", exc.stderr or str(exc)
        if stdout and not outfile.exists():
            outfile.write_text(stdout, encoding="utf-8")
        err = raw_path(scan.id, "nuclei", "nuclei-error")
        err.write_text("\n".join(part for part in [stderr, stdout, str(exc)] if part), encoding="utf-8")
        record_raw(db, scan.id, "nuclei", "nuclei-input", infile)
        record_raw(db, scan.id, "nuclei", "nuclei-error", err)
        if exc.returncode == -1:
            timed_out = True
        else:
            raise
    except Exception as exc:
        err = raw_path(scan.id, "nuclei", "nuclei-error")
        err.write_text(str(exc), encoding="utf-8")
        record_raw(db, scan.id, "nuclei", "nuclei-input", infile)
        record_raw(db, scan.id, "nuclei", "nuclei-error", err)
        raise

    if stdout and not outfile.exists():
        outfile.write_text(stdout, encoding="utf-8")
    if not outfile.exists():
        outfile.write_text("", encoding="utf-8")
    if stderr:
        stderr_out = raw_path(scan.id, "nuclei", "nuclei-stderr")
        stderr_out.write_text(stderr, encoding="utf-8")
        record_raw(db, scan.id, "nuclei", "nuclei-stderr", stderr_out)
    record_raw(db, scan.id, "nuclei", "nuclei-input", infile)
    record_raw(db, scan.id, "nuclei", "nuclei", outfile)

    findings = [
        item for item in parse_nuclei_jsonl(outfile.read_text(errors="ignore"))
        if item.get("severity") in {part.strip().lower() for part in str(config.get("nuclei_severity") or "high,critical").split(",") if part.strip()}
    ]
    existing = {
        (r.template_id, r.matched_at)
        for r in db.query(models.NucleiFinding.template_id, models.NucleiFinding.matched_at).filter_by(scan_id=scan.id).all()
    }
    prior_cache: dict[tuple[str, str], int] = {}
    pending: list[models.NucleiFinding] = []
    for item in findings:
        key = (item["template_id"], item["matched_at"])
        if key in existing:
            continue
        existing.add(key)
        if key not in prior_cache:
            prior = db.query(models.NucleiFinding).filter_by(target_id=scan.target_id, template_id=item["template_id"], matched_at=item["matched_at"]).order_by(models.NucleiFinding.id.asc()).first()
            prior_cache[key] = prior.first_seen_scan_id if prior else scan.id
        severity = item["severity"]
        if severity in stats:
            stats[severity] += 1
        stats["findings"] += 1
        pending.append(models.NucleiFinding(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_cache[key], **item))
        if len(pending) >= NUCLEI_RESULT_BATCH_SIZE:
            db.add_all(pending)
            db.commit()
            pending = []
    if pending:
        db.add_all(pending)
        db.commit()
    if timed_out:
        stats["timed_out"] = True
        stats["error"] = f"Nuclei reached the {stage_timeout}s stage timeout; saved partial output."
    return stats


def _ffuf_host(context: FfufHostContext, command: Callable) -> FfufHostResult:
    safe_url = re.sub(r"[^a-zA-Z0-9_.-]", "_", context.url)
    out = raw_path(context.scan_id, "ffuf", safe_url, "json")
    cmd = None
    try:
        baseline = probe_random_paths(context.url, int(context.config.get("ffuf_baseline_count", 3)), context.headers, context.proxy)
        baseline_out = raw_path(context.scan_id, "ffuf", f"{safe_url}-baseline", "json")
        baseline_out.write_text(json.dumps({"base_url": context.url, "wildcard_baseline": baseline}, indent=2), encoding="utf-8")
        derived_filters = derive_ffuf_filters(baseline)
        filter_size = context.config.get("ffuf_filter_size") or derived_filters.get("filter_size")
        filter_words = context.config.get("ffuf_filter_words") or derived_filters.get("filter_words")
        filter_lines = context.config.get("ffuf_filter_lines") or derived_filters.get("filter_lines")
        cmd = build_ffuf_command(
            context.url, context.wordlist_path, out, context.config.get("extensions", ""),
            bool(context.config.get("ffuf_recursive", False)), context.config.get("ffuf_match_codes", "all"),
            filter_size, int(context.config.get("ffuf_threads", 25)), context.config.get("ffuf_rate"),
            context.headers, context.proxy, bool(context.config.get("ffuf_auto_calibration", True)),
            filter_words, filter_lines,
        )
        _call_command(command, cmd, timeout=int(context.config.get("ffuf_host_timeout", 3600)))
        items_by_key: dict[tuple, dict] = {}
        for item in parse_ffuf_json(out.read_text(errors="ignore")):
            if not item.get("url"):
                continue
            item = classify_ffuf_result(item, baseline)
            if item.get("confidence") != "filtered" and _near_wildcard_baseline(item, baseline):
                try:
                    confirmed = probe_candidate_response(item["url"], context.headers, context.proxy)
                    item.update(confirmed)
                    item = classify_ffuf_result(item, baseline)
                except Exception:
                    pass
            item["normalized_path"] = normalize_content_path(item.get("normalized_path") or item.get("path"))
            item["method"] = item.get("method") or "GET"
            dedupe_key = (*canonical_endpoint_key(context.url + (item.get("normalized_path") or ""), item["method"]),)
            variant = {
                "url": item["url"],
                "status_code": item.get("status_code"),
                "size": item.get("size"),
                "words": item.get("words"),
            }
            if dedupe_key in items_by_key:
                stored = items_by_key[dedupe_key]
                stored["variants"].append(variant)
                stored["observation_count"] = len(stored["variants"])
                continue
            item["variants"] = [variant]
            item["observation_count"] = 1
            items_by_key[dedupe_key] = item
        items = list(items_by_key.values())
        return FfufHostResult(context.url, out, baseline_out=baseline_out, items=items)
    except Exception as e:
        err = {"url": context.url, "command": cmd, "error": str(e), "error_type": type(e).__name__}
        out.write_text(json.dumps(err, indent=2), encoding="utf-8")
        return FfufHostResult(context.url, out, error=err)


def run_ffuf(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    settings = load_settings()
    config = scan.config or {}
    mode = str(config.get("ffuf_mode") or "tech").lower()
    if mode not in {"tech", "generic", "combined"}:
        mode = "tech"
    resolved_wordlist = resolve_ffuf_wordlist(db, config.get("dirb_wordlist_id")) if mode in {"generic", "combined"} else None
    metadata = raw_path(scan.id, "ffuf", "wordlist")
    metadata.write_text(
        f"FFUF mode: {mode}\n"
        f"Generic wordlist: {resolved_wordlist.display_name if resolved_wordlist else 'not used'}\n"
        f"Generic path: {resolved_wordlist.path if resolved_wordlist else 'not used'}\n",
        encoding="utf-8",
    )
    record_raw(db, scan.id, "ffuf", "ffuf-wordlist", metadata)
    query = db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    if urls:
        query = query.filter(models.HttpxResult.url.in_(urls))
    http_rows = query.all()
    max_hosts = config.get("max_ffuf_hosts")
    if max_hosts:
        http_rows = http_rows[: int(max_hosts)]
    stats = {"total_hosts": len(http_rows), "successful_hosts": 0, "failed_hosts": 0, "errors": [], "mode": mode}
    if not http_rows:
        return stats

    existing_paths = {
        (canonical_asset_key(r.base_url), r.normalized_path, r.method)
        for r in db.query(models.DirbResult.base_url, models.DirbResult.normalized_path, models.DirbResult.method).filter_by(scan_id=scan.id).all()
    }
    prior_dir_rows = db.query(models.DirbResult).filter(models.DirbResult.target_id == scan.target_id, models.DirbResult.scan_id != scan.id).all()
    prior_dir_keys = {(canonical_asset_key(r.base_url), r.normalized_path, r.method) for r in prior_dir_rows}
    prior_dir_fingerprints = {r.fingerprint_id for r in prior_dir_rows if r.fingerprint_id}
    fingerprint_cache: dict[str, int] = {}
    command = _command_for_scan(scan.id)
    contexts = [
        FfufHostContext(
            scan.id,
            row.url,
            dict(config),
            dict(settings.headers),
            settings.proxy,
            build_ffuf_wordlist_for_host(scan.id, row.url, row.fingerprints or [], Path(resolved_wordlist.path) if resolved_wordlist else None, mode),
            row.fingerprints or [],
        )
        for row in http_rows
    ]

    prior_dirb_cache: dict[tuple[str, str], int] = {}
    to_add: list[models.DirbResult] = []

    def flush_results(force: bool = False) -> None:
        if not to_add or (not force and len(to_add) < FFUF_RESULT_BATCH_SIZE):
            return
        for obj in to_add:
            db.add(obj)
        db.commit()
        to_add.clear()

    def queue_result_items(result: FfufHostResult) -> None:
        if result.items is None:
            return
        for item in result.items:
            dedupe_key = (canonical_asset_key(result.url), item.get("normalized_path"), item.get("method"))
            if dedupe_key in existing_paths:
                continue
            existing_paths.add(dedupe_key)
            normalized_path = str(item.get("normalized_path") or "")
            method = str(item.get("method") or "GET")
            cache_key = dedupe_key
            if cache_key not in prior_dirb_cache:
                prior = next((row for row in prior_dir_rows if (canonical_asset_key(row.base_url), row.normalized_path, row.method) == dedupe_key), None)
                prior_dirb_cache[cache_key] = prior.first_seen_scan_id if prior else scan.id
            item.pop("body_sample", None)
            item["fingerprint_id"] = get_or_create_response_fingerprint(db, item, fingerprint_cache)
            item["noise_score"], item["noise_reasons"] = noise_score(
                item, duplicate_count=int(item.get("observation_count") or 1), kind="dir"
            )
            item["novelty_score"], item["novelty_reasons"] = novelty_score(
                is_new_identity=dedupe_key not in prior_dir_keys,
                new_fingerprint=item["fingerprint_id"] not in prior_dir_fingerprints,
            )
            to_add.append(models.DirbResult(target_id=scan.target_id, scan_id=scan.id, base_url=result.url, first_seen_scan_id=prior_dirb_cache[cache_key], headers_sent=settings.headers, **item))
            flush_results()

    with ThreadPoolExecutor(max_workers=SCAN_FFUF_PARALLEL) as exc:
        future_map = {exc.submit(_ffuf_host, context, command): context.url for context in contexts}
        for future in as_completed(future_map):
            result = future.result()
            if result.items is not None:
                stats["successful_hosts"] += 1
                record_raw(db, scan.id, "ffuf", "ffuf", result.out)
                if result.baseline_out:
                    record_raw(db, scan.id, "ffuf", "ffuf-baseline", result.baseline_out)
                queue_result_items(result)
            elif result.error:
                stats["failed_hosts"] += 1
                stats["errors"].append(result.error)
                record_raw(db, scan.id, "ffuf", "ffuf-error", result.out)
            flush_results()
    flush_results(force=True)
    record_stage_meta(db, scan.id, "ffuf", "ffuf-summary", stats)
    return stats


def _persist_parameter_items(db: Session, scan: models.Scan, sources: Sequence[tuple[str, object]]) -> dict:
    stats = {"total_sources": len(sources), "parameters": 0, "suspicious": 0, "failed": False, "lines": 0, "parse_errors": 0}
    current_rows = db.query(models.ParameterResult).filter_by(scan_id=scan.id).all()
    objects_by_key = {
        (
            r.asset_key or canonical_asset_key(r.source_url),
            r.normalized_path or normalize_path_pattern(r.source_url),
            r.method,
            r.param,
        ): r
        for r in current_rows
    }
    existing = set(objects_by_key)
    prior_rows = db.query(models.ParameterResult).filter(models.ParameterResult.target_id == scan.target_id, models.ParameterResult.scan_id != scan.id).all()
    prior_by_key = {
        (
            r.asset_key or canonical_asset_key(r.source_url),
            r.normalized_path or normalize_path_pattern(r.source_url),
            r.method,
            r.param,
        ): r
        for r in prior_rows
    }
    prior_cache: dict[tuple[str, str, str, str], int] = {}
    to_add: list[models.ParameterResult] = []

    def flush(force: bool = False) -> None:
        if not to_add or (not force and len(to_add) < PARAMETER_RESULT_BATCH_SIZE):
            return
        db.add_all(to_add)
        db.commit()
        to_add.clear()

    def queue(parsed_items: list[dict]) -> None:
        for item in parsed_items:
            item["asset_key"] = item.get("asset_key") or canonical_asset_key(item["source_url"])
            item["normalized_path"] = item.get("normalized_path") or normalize_path_pattern(item["source_url"])
            item["method"] = str(item.get("method") or "GET").upper()
            key = (item["asset_key"], item["normalized_path"], item["method"], item["param"])
            variant = {
                "source_url": item["source_url"],
                "sample_value": item.get("sample_value"),
                "source": item.get("source"),
            }
            if key in existing:
                stored = objects_by_key.get(key)
                if stored is not None:
                    variants = list(stored.variants or [])
                    if variant not in variants:
                        variants.append(variant)
                    stored.variants = variants
                    stored.observation_count = int(stored.observation_count or 1) + 1
                    stored.noise_score, stored.noise_reasons = noise_score(
                        {"source_url": stored.source_url},
                        duplicate_count=stored.observation_count,
                        kind="parameter",
                    )
                continue
            existing.add(key)
            cache_key = key
            if cache_key not in prior_cache:
                prior = prior_by_key.get(key)
                prior_cache[cache_key] = prior.first_seen_scan_id if prior else scan.id
            item["variants"] = [variant]
            item["observation_count"] = 1
            item["noise_score"], item["noise_reasons"] = noise_score(item, kind="parameter")
            item["novelty_score"], item["novelty_reasons"] = novelty_score(is_new_identity=key not in prior_by_key)
            obj = models.ParameterResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_cache[cache_key], **item)
            objects_by_key[key] = obj
            to_add.append(obj)
            stats["parameters"] += 1
            if item.get("suspicious"):
                stats["suspicious"] += 1
            flush()

    for source, value in sources:
        if source.startswith("arjun-"):
            queue(parse_arjun_json(str(value or ""), source))
            continue
        if isinstance(value, Path):
            try:
                with value.open("r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        stats["lines"] += 1
                        try:
                            queue(extract_parameters_from_urls(line, source))
                        except Exception:
                            stats["parse_errors"] += 1
            except OSError as exc:
                stats["failed"] = True
                stats["error"] = str(exc)
        else:
            try:
                queue(extract_parameters_from_urls(str(value or ""), source))
            except Exception as exc:
                stats["failed"] = True
                stats["parse_errors"] += 1
                stats["error"] = str(exc)
    flush(force=True)
    return stats


def _persist_parameter_texts(db: Session, scan: models.Scan, raw_texts: list[tuple[str, str]]) -> dict:
    return _persist_parameter_items(db, scan, raw_texts)


def compact_jsonl_raw(path: Path, max_mb: int, strip_keys: set[str] | None = None) -> dict:
    strip_keys = strip_keys or {"body", "raw"}
    stats = {"path": str(path), "original_bytes": path.stat().st_size if path.exists() else 0, "compacted": False, "gzip_path": None}
    if not path.exists() or stats["original_bytes"] <= max_mb * 1024 * 1024:
        return stats
    compact = path.with_suffix(path.suffix + ".compact")
    gz = path.with_suffix(path.suffix + ".gz")

    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items() if k not in strip_keys}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    with path.open("r", encoding="utf-8", errors="ignore") as src, compact.open("w", encoding="utf-8") as dst, gzip.open(gz, "wt", encoding="utf-8") as zipped:
        for line in src:
            zipped.write(line)
            try:
                dst.write(json.dumps(scrub(json.loads(line)), separators=(",", ":")) + "\n")
            except json.JSONDecodeError:
                dst.write(line)
    compact.replace(path)
    stats.update({"compacted": True, "gzip_path": str(gz), "compacted_bytes": path.stat().st_size})
    return stats


def run_parameters(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    command = _command_for_scan(scan.id)
    domain = scan.target.domain
    query = db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    if urls:
        query = query.filter(models.HttpxResult.url.in_(urls))
    live_urls = [r.url for r in query.all()]
    max_katana_urls = config.get("max_katana_urls")
    if max_katana_urls:
        live_urls = live_urls[: int(max_katana_urls)]
    raw_sources: list[tuple[str, object]] = []
    parameter_timeout = int(config.get("parameter_timeout", 240))
    katana_crawl_duration = str(config.get("katana_crawl_duration") or "2m")

    gau_out = raw_path(scan.id, "parameters", "gau")
    try:
        stdout, stderr = _call_command(command, build_gau_command(domain), timeout=min(parameter_timeout, 120))
    except CommandError as exc:
        stdout, stderr = exc.stdout or "", exc.stderr or str(exc)
        raw_path(scan.id, "parameters", "gau-note").write_text(str(exc), encoding="utf-8")
    except Exception as exc:
        stdout, stderr = "", str(exc)
        raw_path(scan.id, "parameters", "gau-note").write_text(str(exc), encoding="utf-8")
    gau_out.write_text(stdout, encoding="utf-8")
    if stderr:
        raw_path(scan.id, "parameters", "gau-stderr").write_text(stderr, encoding="utf-8")
    record_raw(db, scan.id, "parameters", "gau", gau_out)
    raw_sources.append(("gau", stdout))

    if live_urls:
        katana_in = raw_path(scan.id, "parameters", "katana-input")
        katana_out = raw_path(scan.id, "parameters", "katana")
        katana_in.write_text("\n".join(live_urls), encoding="utf-8")
        try:
            _call_command(
                command,
                build_katana_command(
                    katana_in,
                    katana_out,
                    int(config.get("katana_depth", 2)),
                    bool(config.get("run_katana_headless", False)),
                    katana_crawl_duration,
                ),
                timeout=parameter_timeout,
            )
        except CommandError as exc:
            if not katana_out.exists():
                katana_out.write_text(exc.stdout or "", encoding="utf-8")
            raw_path(scan.id, "parameters", "katana-note").write_text(str(exc), encoding="utf-8")
        except Exception as exc:
            if not katana_out.exists():
                katana_out.write_text("", encoding="utf-8")
            raw_path(scan.id, "parameters", "katana-note").write_text(str(exc), encoding="utf-8")
        if not katana_out.exists():
            katana_out.write_text("", encoding="utf-8")
        record_raw(db, scan.id, "parameters", "katana", katana_out)
        raw_sources.append(("katana-headless" if config.get("run_katana_headless", False) else "katana", katana_out))

    stats = _persist_parameter_items(db, scan, raw_sources)
    stats["katana_input_urls"] = len(live_urls)
    if live_urls:
        compact_stats = compact_jsonl_raw(katana_out, int(config.get("max_katana_output_mb", 250)))
        stats["katana_raw"] = compact_stats
        record_stage_meta(db, scan.id, "parameters", "katana-raw-summary", compact_stats)
    record_stage_meta(db, scan.id, "parameters", "parameters-summary", stats)
    return stats


def run_arjun(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    command = _command_for_scan(scan.id)
    settings = load_settings()
    parameter_timeout = int(config.get("parameter_timeout", 240))
    selected_urls = [url for url in (urls or config.get("subset_urls") or []) if url]
    if selected_urls:
        endpoint_urls = set(selected_urls)
    else:
        endpoint_urls = {
            r.source_url
            for r in db.query(models.ParameterResult.source_url, models.ParameterResult.source)
            .filter_by(scan_id=scan.id)
            .all()
            if r.source_url and not str(r.source or "").startswith("arjun-")
        }
    if not endpoint_urls:
        skipped_out = raw_path(scan.id, "arjun", "arjun-skipped")
        skipped_out.write_text("No parameter discovery endpoint URLs were available for Arjun.\n", encoding="utf-8")
        record_raw(db, scan.id, "arjun", "arjun-skipped", skipped_out)
        return {"total_sources": 0, "parameters": 0, "suspicious": 0, "failed": False}

    arjun_in = raw_path(scan.id, "arjun", "arjun-input")
    arjun_methods = [m.strip().upper() for m in str(config.get("arjun_methods") or "GET").split(",") if m.strip()]
    arjun_methods = [m for m in arjun_methods if m in {"GET", "POST", "JSON", "XML", "HEADERS"}] or ["GET"]
    arjun_in.write_text("\n".join(sorted(endpoint_urls)), encoding="utf-8")
    record_raw(db, scan.id, "arjun", "arjun-input", arjun_in)
    headers = {"User-Agent": settings.user_agent, **(settings.headers or {})}
    arjun_timeout = int(config.get("arjun_timeout", max(parameter_timeout, 240)))
    raw_texts: list[tuple[str, str]] = []
    for method in arjun_methods:
        arjun_out = raw_path(scan.id, "arjun", f"arjun-{method.lower()}", "json")
        try:
            _call_command(
                command,
                build_arjun_command(
                    arjun_in,
                    arjun_out,
                    method,
                    int(config.get("arjun_threads", 5)),
                    int(config.get("arjun_request_timeout", 10)),
                    headers,
                    bool(config.get("arjun_stable", True)),
                ),
                timeout=arjun_timeout,
            )
        except CommandError as exc:
            if not arjun_out.exists():
                arjun_out.write_text(exc.stdout or "", encoding="utf-8")
            raw_path(scan.id, "arjun", f"arjun-{method.lower()}-note").write_text(str(exc), encoding="utf-8")
        except Exception as exc:
            if not arjun_out.exists():
                arjun_out.write_text("", encoding="utf-8")
            raw_path(scan.id, "arjun", f"arjun-{method.lower()}-note").write_text(str(exc), encoding="utf-8")
        if not arjun_out.exists():
            arjun_out.write_text("", encoding="utf-8")
        record_raw(db, scan.id, "arjun", f"arjun-{method.lower()}", arjun_out)
        raw_texts.append((f"arjun-{method.lower()}", arjun_out.read_text(errors="ignore")))

    return _persist_parameter_texts(db, scan, raw_texts)


def run_screenshots(db: Session, scan: models.Scan) -> None:
    settings = load_settings()
    command = _command_for_scan(scan.id)
    config = scan.config or {}
    urls = [r.url for r in db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id).all()]
    max_urls = config.get("max_screenshot_urls")
    if max_urls:
        urls = urls[: int(max_urls)]
    if not urls:
        return
    infile = raw_path(scan.id, "screenshots", "input")
    outdir = SCREEN_DIR / f"scan-{scan.id}"
    outdir.mkdir(parents=True, exist_ok=True)
    url_by_stem: dict[str, str] = {}
    for url in urls:
        for stem in gowitness_stem_candidates(url):
            url_by_stem.setdefault(stem, url)
    infile.write_text("\n".join(urls))
    try:
        _call_command(command, build_gowitness_command(infile, outdir, settings.user_agent, settings.proxy), timeout=3600)
    except Exception as e:
        err = raw_path(scan.id, "screenshots", "gowitness-error")
        err.write_text(str(e))
        record_raw(db, scan.id, "screenshots", "gowitness-error", err)
        raise
    images = list(outdir.glob("*.png")) + list(outdir.glob("*.jpg")) + list(outdir.glob("*.jpeg"))
    existing_urls = {r.url for r in db.query(models.Screenshot.url).filter_by(scan_id=scan.id).all()}
    saved_urls = set(existing_urls)
    for image in images:
        url = url_by_stem.get(image.stem) or decode_gowitness_stem(image.stem)
        if url in existing_urls:
            continue
        existing_urls.add(url)
        saved_urls.add(url)
        db.add(models.Screenshot(target_id=scan.target_id, scan_id=scan.id, url=url, image_path=str(image)))
    db.commit()
    saved_for_input = len([url for url in urls if url in saved_urls])
    record_stage_meta(db, scan.id, "screenshots", "screenshots-summary", {
        "input_urls": len(urls),
        "saved": saved_for_input,
        "failed": max(0, len(urls) - saved_for_input),
        "screenshot_files": len(images),
    })


def execute_scan(db: Session, scan_id: int, stage_only: str | None = None) -> None:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        return
    try:
        ensure_scan_not_stopped(db, scan)
        clear_scan_raw(db, scan_id, stage_only)
        scan.started_at = datetime.now(UTC)
        set_scan(db, scan, stage_only or "subdomains", 5)
        ffuf_stats = None
        nuclei_stats = None
        urls: list[str] | None = None

        if stage_only in (None, "subdomains"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "subdomains", 10)
            enumerate_subdomains(db, scan)
            ensure_scan_not_stopped(db, scan)

        if (scan.config or {}).get("run_naabu", True) and stage_only in (None, "naabu"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "naabu", 30)
            run_naabu(db, scan)
            ensure_scan_not_stopped(db, scan)

        if stage_only in (None, "httpx"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "httpx", 45)
            urls = run_httpx(db, scan)
            ensure_scan_not_stopped(db, scan)
        elif scan.config:
            urls = scan.config.get("subset_urls")

        if stage_only in (None, "wappalyzer", "ffuf", "parameters", "js_intel", "nuclei"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "wappalyzer", 58)
            run_wappalyzer(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if stage_only in (None, "js_intel"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "js_intel", 63)
            run_js_intel(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if (scan.config or {}).get("run_ffuf", True) and stage_only in (None, "ffuf"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "ffuf", 70)
            ffuf_stats = run_ffuf(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if (scan.config or {}).get("run_nuclei", False) and stage_only in (None, "nuclei"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "nuclei", 76)
            nuclei_stats = run_nuclei(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if (scan.config or {}).get("run_parameters", True) and stage_only in (None, "parameters", "ffuf"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "parameters", 80)
            run_parameters(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if stage_only == "arjun":
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "arjun", 84)
            run_arjun(db, scan, urls)
            ensure_scan_not_stopped(db, scan)

        if (scan.config or {}).get("run_screenshots", True) and stage_only in (None, "screenshots"):
            ensure_scan_not_stopped(db, scan)
            set_scan(db, scan, "screenshots", 90)
            run_screenshots(db, scan)
            ensure_scan_not_stopped(db, scan)

        scan.finished_at = datetime.now(UTC)
        if ffuf_stats and ffuf_stats.get("failed_hosts"):
            error = f"FFUF had {ffuf_stats['failed_hosts']} host failure(s); {ffuf_stats.get('successful_hosts', 0)} host(s) completed."
            set_scan(db, scan, "partial", 100, "partial", error)
        elif nuclei_stats and nuclei_stats.get("timed_out"):
            set_scan(db, scan, "partial", 100, "partial", nuclei_stats.get("error"))
        else:
            set_scan(db, scan, "complete", 100, "complete")
    except ScanStopped:
        db.rollback()
        scan = db.get(models.Scan, scan_id)
        if scan:
            progress = scan.progress or 0
            scan.finished_at = datetime.now(UTC)
            set_scan(db, scan, "stopped", progress, "stopped", "Scan stopped by user")
    except Exception as e:
        db.rollback()
        scan = db.get(models.Scan, scan_id)
        if scan:
            progress = scan.progress or 0
            scan.finished_at = datetime.now(UTC)
            if scan.status == "stopping":
                set_scan(db, scan, "stopped", progress, "stopped", "Scan stopped by user")
            else:
                set_scan(db, scan, "failed", progress, "failed", str(e))
