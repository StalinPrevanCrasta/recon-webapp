import hashlib
import json
import logging
import os
import re
import secrets
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlparse

import httpx as pyhttpx
from sqlalchemy.orm import Session

from app import models
from app.recon.runner import CommandError, CommandRunner, run_command as _run_command
from app.recon.wrappers import (
    build_amass_command, build_arjun_command, build_ffuf_command, build_gau_command, build_gowitness_command, build_httpx_command, build_katana_command, build_naabu_command,
    build_puredns_command, build_subfinder_command, normalize_content_path, parse_ffuf_json, parse_httpx_jsonl,
    parse_naabu_jsonl, build_wappalyzer_command, parse_wappalyzer_json, extract_endpoint_urls, extract_parameters_from_urls, parse_arjun_json,
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


def raw_path(scan_id: int, stage: str, tool: str, suffix: str = "txt") -> Path:
    path = RAW_DIR / f"scan-{scan_id}" / stage / f"{tool}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def record_raw(db: Session, scan_id: int, stage: str, tool: str, path: Path) -> None:
    db.add(models.RawOutput(scan_id=scan_id, stage=stage, tool=tool, path=str(path)))
    db.commit()


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
    return (item.get("status_code"), item.get("size"), item.get("words"), item.get("lines"), item.get("body_hash"))


def probe_random_paths(base_url: str, count: int = 3, headers: dict[str, str] | None = None, proxy: str | None = None, timeout: int = 10) -> list[dict]:
    rows: list[dict] = []
    for _ in range(count):
        path = f"/__ffuf_baseline_{secrets.token_hex(8)}"
        url = base_url.rstrip("/") + path
        try:
            response = pyhttpx.get(url, headers=headers or {}, proxy=proxy, follow_redirects=False, timeout=timeout)
            body = response.content or b""
            text = body.decode(response.encoding or "utf-8", errors="ignore")
            rows.append({
                "url": url, "path": path, "status_code": response.status_code,
                "size": len(body), "words": len(text.split()), "lines": len(text.splitlines()),
                "content_type": response.headers.get("content-type"),
                "redirect_location": response.headers.get("location"),
                "body_hash": hashlib.sha256(body).hexdigest(),
            })
        except Exception as exc:
            rows.append({"url": url, "path": path, "error": str(exc)})
    return rows


def derive_ffuf_filters(baseline: list[dict]) -> dict[str, str]:
    valid = [row for row in baseline if not row.get("error")]
    if len(valid) < 2:
        return {}
    keys = ["status_code", "size", "words", "lines", "body_hash"]
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
    result_tuple = (result.get("status_code"), result.get("size"), result.get("words"), result.get("lines"))
    baseline_tuples = {(row.get("status_code"), row.get("size"), row.get("words"), row.get("lines")) for row in baseline if not row.get("error")}
    if result_tuple in baseline_tuples:
        classified["confidence"] = "filtered"
        classified["filtered_reason"] = "matches wildcard baseline response"
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


def enumerate_subdomains(db: Session, scan: models.Scan) -> list[str]:
    config = scan.config or {}
    target = scan.target
    domain = target.domain
    brute_wordlists = _subdomain_bruteforce_wordlists(db, config)
    depth_max = int(config.get("recursion_depth", 2))
    subfinder_timeout = int(config.get("subfinder_timeout", 300))
    amass_timeout = int(config.get("amass_timeout", 600))
    command = _command_for_scan(scan.id)
    seen: set[str] = {domain}
    batch_upsert_subdomains(db, target.id, scan.id, [SubdomainDiscovery(domain, "root", 0)])
    db.commit()

    subfinder_out = raw_path(scan.id, "subdomains", "subfinder")
    crtsh_out = raw_path(scan.id, "subdomains", "crtsh")
    with ThreadPoolExecutor(max_workers=SCAN_CONCURRENT_ENUM) as exc:
        futures = [
            exc.submit(_run_enum_tool, "subfinder", build_subfinder_command, domain, subfinder_out, subfinder_timeout, command),
            exc.submit(_run_crtsh, domain, crtsh_out),
        ]
        if config.get("run_amass", False):
            amass_out = raw_path(scan.id, "subdomains", "amass")
            futures.append(exc.submit(_run_enum_tool, "amass", build_amass_command, domain, amass_out, amass_timeout, command))
        for future in as_completed(futures):
            result = future.result()
            _persist_enum_result(db, scan, result.tool, result, seen)

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
    hosts = [r.name for r in db.query(models.Subdomain).filter_by(target_id=scan.target_id).all()]
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
    subs = [r.name for r in db.query(models.Subdomain).filter_by(target_id=scan.target_id).all()]
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
    urls = []
    existing_urls = {r.url for r in db.query(models.HttpxResult.url).filter_by(scan_id=scan.id).all()}
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
        urls.append(url)
        if url in existing_urls:
            continue
        if url not in prior_map:
            prior = db.query(models.HttpxResult).filter_by(target_id=scan.target_id, url=url).order_by(models.HttpxResult.id.asc()).first()
            prior_map[url] = prior.first_seen_scan_id if prior else scan.id
        to_add.append(models.HttpxResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_map[url], headers_sent={"User-Agent": settings.user_agent, **headers}, **item))
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
        seen_keys: set[tuple] = set()
        items = []
        for item in parse_ffuf_json(out.read_text(errors="ignore")):
            if not item.get("url"):
                continue
            item = classify_ffuf_result(item, baseline)
            item["normalized_path"] = normalize_content_path(item.get("normalized_path") or item.get("path"))
            item["method"] = item.get("method") or "GET"
            dedupe_key = (context.url, item.get("normalized_path"), item.get("method"))
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            items.append(item)
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
    stats = {"total_hosts": len(http_rows), "successful_hosts": 0, "failed_hosts": 0, "errors": [], "mode": mode}
    if not http_rows:
        return stats

    existing_paths = {
        (r.base_url, r.normalized_path, r.method)
        for r in db.query(models.DirbResult.base_url, models.DirbResult.normalized_path, models.DirbResult.method).filter_by(scan_id=scan.id).all()
    }
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
            dedupe_key = (result.url, item.get("normalized_path"), item.get("method"))
            if dedupe_key in existing_paths:
                continue
            existing_paths.add(dedupe_key)
            normalized_path = str(item.get("normalized_path") or "")
            method = str(item.get("method") or "GET")
            cache_key = (normalized_path, method)
            if cache_key not in prior_dirb_cache:
                prior = db.query(models.DirbResult).filter_by(target_id=scan.target_id, normalized_path=normalized_path, method=method).order_by(models.DirbResult.id.asc()).first()
                prior_dirb_cache[cache_key] = prior.first_seen_scan_id if prior else scan.id
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
    return stats


def run_parameters(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    config = scan.config or {}
    command = _command_for_scan(scan.id)
    settings = load_settings()
    domain = scan.target.domain
    query = db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500)
    if urls:
        query = query.filter(models.HttpxResult.url.in_(urls))
    live_urls = [r.url for r in query.all()]
    stats = {"total_sources": 0, "parameters": 0, "suspicious": 0, "failed": False}

    raw_texts: list[tuple[str, str]] = []
    endpoint_urls: set[str] = set()
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
    raw_texts.append(("gau", stdout))
    endpoint_urls.update(extract_endpoint_urls(stdout))

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
        katana_text = katana_out.read_text(errors="ignore")
        raw_texts.append(("katana-headless" if config.get("run_katana_headless", False) else "katana", katana_text))
        endpoint_urls.update(extract_endpoint_urls(katana_text))

    if config.get("run_arjun", True) and endpoint_urls:
        arjun_in = raw_path(scan.id, "parameters", "arjun-input")
        arjun_methods = [m.strip().upper() for m in str(config.get("arjun_methods") or "GET").split(",") if m.strip()]
        arjun_methods = [m for m in arjun_methods if m in {"GET", "POST", "JSON", "XML", "HEADERS"}] or ["GET"]
        arjun_in.write_text("\n".join(sorted(endpoint_urls)), encoding="utf-8")
        headers = {"User-Agent": settings.user_agent, **(settings.headers or {})}
        arjun_timeout = int(config.get("arjun_timeout", max(parameter_timeout, 240)))
        for method in arjun_methods:
            arjun_out = raw_path(scan.id, "parameters", f"arjun-{method.lower()}", "json")
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
                raw_path(scan.id, "parameters", f"arjun-{method.lower()}-note").write_text(str(exc), encoding="utf-8")
            except Exception as exc:
                if not arjun_out.exists():
                    arjun_out.write_text("", encoding="utf-8")
                raw_path(scan.id, "parameters", f"arjun-{method.lower()}-note").write_text(str(exc), encoding="utf-8")
            if not arjun_out.exists():
                arjun_out.write_text("", encoding="utf-8")
            record_raw(db, scan.id, "parameters", f"arjun-{method.lower()}", arjun_out)
            raw_texts.append((f"arjun-{method.lower()}", arjun_out.read_text(errors="ignore")))

    existing = {
        (r.source_url, r.param, r.method)
        for r in db.query(models.ParameterResult.source_url, models.ParameterResult.param, models.ParameterResult.method).filter_by(scan_id=scan.id).all()
    }
    prior_cache: dict[tuple[str, str], int] = {}
    to_add: list[models.ParameterResult] = []
    for source, text in raw_texts:
        parsed_items = parse_arjun_json(text, source) if source.startswith("arjun-") else extract_parameters_from_urls(text, source)
        for item in parsed_items:
            key = (item["source_url"], item["param"], item["method"])
            if key in existing:
                continue
            existing.add(key)
            cache_key = (item["param"], item["method"])
            if cache_key not in prior_cache:
                prior = db.query(models.ParameterResult).filter_by(target_id=scan.target_id, param=item["param"], method=item["method"]).order_by(models.ParameterResult.id.asc()).first()
                prior_cache[cache_key] = prior.first_seen_scan_id if prior else scan.id
            to_add.append(models.ParameterResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior_cache[cache_key], **item))
            stats["parameters"] += 1
            if item.get("suspicious"):
                stats["suspicious"] += 1
            if len(to_add) >= FFUF_RESULT_BATCH_SIZE:
                for obj in to_add:
                    db.add(obj)
                db.commit()
                to_add.clear()
    for obj in to_add:
        db.add(obj)
    db.commit()
    stats["total_sources"] = len(raw_texts)
    return stats


def run_screenshots(db: Session, scan: models.Scan) -> None:
    settings = load_settings()
    command = _command_for_scan(scan.id)
    urls = [r.url for r in db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code.in_([200, 301, 302, 307, 401, 403])).all()]
    if not urls:
        return
    infile = raw_path(scan.id, "screenshots", "input")
    outdir = SCREEN_DIR / f"scan-{scan.id}"
    outdir.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(urls))
    try:
        _call_command(command, build_gowitness_command(infile, outdir, settings.user_agent, settings.proxy), timeout=3600)
    except Exception as e:
        err = raw_path(scan.id, "screenshots", "gowitness-error")
        err.write_text(str(e))
        record_raw(db, scan.id, "screenshots", "gowitness-error", err)
        raise
    images = list(outdir.glob("*.png")) + list(outdir.glob("*.jpg")) + list(outdir.glob("*.jpeg"))
    for image in images:
        stem = image.stem.replace("_", "://", 1) if "_" in image.stem else image.stem
        db.add(models.Screenshot(target_id=scan.target_id, scan_id=scan.id, url=stem, image_path=str(image)))
    db.commit()


def execute_scan(db: Session, scan_id: int, stage_only: str | None = None) -> None:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        return
    clear_scan_raw(db, scan_id, stage_only)
    scan.started_at = datetime.now(UTC)
    set_scan(db, scan, stage_only or "subdomains", 5)
    try:
        ffuf_stats = None
        urls: list[str] | None = None

        if stage_only in (None, "subdomains"):
            set_scan(db, scan, "subdomains", 10)
            enumerate_subdomains(db, scan)

        if (scan.config or {}).get("run_naabu", True) and stage_only in (None, "naabu"):
            set_scan(db, scan, "naabu", 30)
            run_naabu(db, scan)

        if stage_only in (None, "httpx"):
            set_scan(db, scan, "httpx", 45)
            urls = run_httpx(db, scan)
        elif scan.config:
            urls = scan.config.get("subset_urls")

        if stage_only in (None, "wappalyzer", "ffuf", "parameters"):
            set_scan(db, scan, "wappalyzer", 58)
            run_wappalyzer(db, scan, urls)

        if (scan.config or {}).get("run_ffuf", True) and stage_only in (None, "ffuf"):
            set_scan(db, scan, "ffuf", 68)
            ffuf_stats = run_ffuf(db, scan, urls)

        if (scan.config or {}).get("run_parameters", True) and stage_only in (None, "parameters", "ffuf"):
            set_scan(db, scan, "parameters", 78)
            run_parameters(db, scan, urls)

        if (scan.config or {}).get("run_screenshots", True) and stage_only in (None, "screenshots"):
            set_scan(db, scan, "screenshots", 88)
            run_screenshots(db, scan)

        scan.finished_at = datetime.now(UTC)
        if ffuf_stats and ffuf_stats.get("failed_hosts"):
            error = f"FFUF had {ffuf_stats['failed_hosts']} host failure(s); {ffuf_stats.get('successful_hosts', 0)} host(s) completed."
            set_scan(db, scan, "partial", 100, "partial", error)
        else:
            set_scan(db, scan, "complete", 100, "complete")
    except Exception as e:
        db.rollback()
        scan = db.get(models.Scan, scan_id)
        if scan:
            progress = scan.progress or 0
            scan.finished_at = datetime.now(UTC)
            set_scan(db, scan, "failed", progress, "failed", str(e))
