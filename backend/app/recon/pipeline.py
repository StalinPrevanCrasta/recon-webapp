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

import httpx as pyhttpx
from sqlalchemy.orm import Session

from app import models
from app.recon.runner import CommandRunner, run_command as _run_command
from app.recon.wrappers import (
    build_ffuf_command, build_gowitness_command, build_httpx_command,
    build_puredns_command, build_subfinder_command, normalize_content_path, parse_ffuf_json, parse_httpx_jsonl,
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

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
RAW_DIR = DATA_DIR / "raw"
SCREEN_DIR = DATA_DIR / "screenshots"
WORDLIST_DIR = DATA_DIR / "wordlists"
DEFAULT_RESOLVERS = DATA_DIR / "resolvers.txt"
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


@dataclass(frozen=True)
class FfufHostResult:
    url: str
    out: Path
    baseline_out: Path | None = None
    items: list[dict] | None = None
    error: dict | None = None


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
    batch_upsert_subdomains(db, scan.target_id, scan.id, [SubdomainDiscovery(name, source, depth) for name in names])
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
    command = _command_for_scan(scan.id)
    seen: set[str] = set()

    subfinder_out = raw_path(scan.id, "subdomains", "subfinder")
    crtsh_out = raw_path(scan.id, "subdomains", "crtsh")
    with ThreadPoolExecutor(max_workers=SCAN_CONCURRENT_ENUM) as exc:
        futures = [
            exc.submit(_run_enum_tool, "subfinder", build_subfinder_command, domain, subfinder_out, subfinder_timeout, command),
            exc.submit(_run_crtsh, domain, crtsh_out),
        ]
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
                            batch_upsert_subdomains(db, target.id, scan.id, [SubdomainDiscovery(name, brute_wordlist.source, depth) for name in names])
                            next_frontier.update(names)
                    except Exception as e:
                        out.write_text(str(e))
                        record_raw(db, scan.id, f"subdomains-depth-{depth}", f"{brute_wordlist.source}-error", out)
            mutations = [SubdomainDiscovery(name, "mutation", depth) for name in mutate_names(next_frontier or frontier, domain) if name not in seen]
            for item in mutations:
                seen.add(item.name)
            if mutations:
                batch_upsert_subdomains(db, target.id, scan.id, mutations)
            frontier = next_frontier
            db.commit()
    db.commit()
    return sorted(seen)


def run_httpx(db: Session, scan: models.Scan) -> list[str]:
    settings = load_settings()
    command = _command_for_scan(scan.id)
    subs = [r.name for r in db.query(models.Subdomain).filter_by(target_id=scan.target_id).all()]
    infile = raw_path(scan.id, "httpx", "input")
    outfile = raw_path(scan.id, "httpx", "httpx", "jsonl")
    outfile.parent.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(sorted(set(subs))))
    if not subs:
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
    resolved_wordlist = resolve_ffuf_wordlist(db, config.get("dirb_wordlist_id"))
    metadata = raw_path(scan.id, "ffuf", "wordlist")
    metadata.write_text(f"Using {resolved_wordlist.source} FFUF wordlist: {resolved_wordlist.display_name}\nPath: {resolved_wordlist.path}\n", encoding="utf-8")
    record_raw(db, scan.id, "ffuf", "ffuf-wordlist", metadata)
    urls = urls or [r.url for r in db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500).all()]
    stats = {"total_hosts": len(urls), "successful_hosts": 0, "failed_hosts": 0, "errors": []}
    if not urls:
        return stats

    existing_paths = {
        (r.base_url, r.normalized_path, r.method)
        for r in db.query(models.DirbResult.base_url, models.DirbResult.normalized_path, models.DirbResult.method).filter_by(scan_id=scan.id).all()
    }
    command = _command_for_scan(scan.id)
    contexts = [
        FfufHostContext(scan.id, url, dict(config), dict(settings.headers), settings.proxy, Path(resolved_wordlist.path))
        for url in urls
    ]

    results: list[FfufHostResult] = []
    with ThreadPoolExecutor(max_workers=SCAN_FFUF_PARALLEL) as exc:
        future_map = {exc.submit(_ffuf_host, context, command): context.url for context in contexts}
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            if result.items is not None:
                stats["successful_hosts"] += 1
                record_raw(db, scan.id, "ffuf", "ffuf", result.out)
                if result.baseline_out:
                    record_raw(db, scan.id, "ffuf", "ffuf-baseline", result.baseline_out)
            elif result.error:
                stats["failed_hosts"] += 1
                stats["errors"].append(result.error)
                record_raw(db, scan.id, "ffuf", "ffuf-error", result.out)

    prior_dirb_cache: dict[tuple[str, str], int] = {}
    to_add = []
    for result in results:
        if result.items is None:
            continue
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
            if len(to_add) >= SCAN_BATCH_SIZE:
                for obj in to_add:
                    db.add(obj)
                db.flush()
                to_add.clear()
    for obj in to_add:
        db.add(obj)
    db.commit()
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

        if stage_only in (None, "httpx"):
            set_scan(db, scan, "httpx", 40)
            urls = run_httpx(db, scan)
        elif scan.config:
            urls = scan.config.get("subset_urls")

        if (scan.config or {}).get("run_ffuf", True) and stage_only in (None, "ffuf"):
            set_scan(db, scan, "ffuf", 65)
            ffuf_stats = run_ffuf(db, scan, urls)

        if (scan.config or {}).get("run_screenshots", True) and stage_only in (None, "screenshots"):
            set_scan(db, scan, "screenshots", 85)
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
