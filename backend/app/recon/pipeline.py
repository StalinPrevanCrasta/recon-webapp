import json
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx as pyhttpx
from sqlalchemy.orm import Session

from app import models
from app.recon.runner import run_command
from app.recon.wrappers import (
    build_amass_command, build_ffuf_command, build_gowitness_command, build_httpx_command,
    build_puredns_command, build_subfinder_command, parse_ffuf_json, parse_httpx_jsonl,
)
from app.recon.wordlists import resolve_ffuf_wordlist
from app.settings_store import load_settings

DATA_DIR = Path(__import__('os').getenv("RECON_DATA_DIR", "/data"))
RAW_DIR = DATA_DIR / "raw"
SCREEN_DIR = DATA_DIR / "screenshots"
WORDLIST_DIR = DATA_DIR / "wordlists"
DEFAULT_RESOLVERS = DATA_DIR / "resolvers.txt"

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

def upsert_subdomain(db: Session, target_id: int, scan_id: int, name: str, source: str, depth: int) -> None:
    name = name.strip().lower().rstrip('.')
    if not name:
        return
    row = db.query(models.Subdomain).filter_by(target_id=target_id, name=name).one_or_none()
    if row:
        row.scan_id = scan_id
        row.sources = sorted(set((row.sources or []) + [source]))
        row.depths = sorted(set((row.depths or []) + [depth]))
    else:
        db.add(models.Subdomain(target_id=target_id, scan_id=scan_id, name=name, sources=[source], depths=[depth], first_seen_scan_id=scan_id))

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
    except Exception:
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

def enumerate_subdomains(db: Session, scan: models.Scan) -> list[str]:
    config = scan.config or {}
    target = scan.target
    domain = target.domain
    wordlist = db.get(models.Wordlist, config.get("subdomain_wordlist_id")) if config.get("subdomain_wordlist_id") else None
    depth_max = int(config.get("recursion_depth", 2))
    seen: set[str] = set()
    for tool, builder in [("subfinder", build_subfinder_command), ("amass", build_amass_command)]:
        out = raw_path(scan.id, "subdomains", tool)
        try:
            run_command(builder(domain, out), timeout=900)
            record_raw(db, scan.id, "subdomains", tool, out)
            for name in out.read_text(errors="ignore").splitlines():
                seen.add(name.strip().lower())
                upsert_subdomain(db, target.id, scan.id, name, tool, 0)
        except Exception as e:
            out.write_text(str(e))
            record_raw(db, scan.id, "subdomains", f"{tool}-error", out)
    ctnames = crtsh(domain)
    ctout = raw_path(scan.id, "subdomains", "crtsh")
    ctout.write_text("\n".join(sorted(ctnames)))
    record_raw(db, scan.id, "subdomains", "crtsh", ctout)
    for name in ctnames:
        seen.add(name); upsert_subdomain(db, target.id, scan.id, name, "crtsh", 0)
    frontier = set(seen) or {domain}
    if wordlist:
        if not DEFAULT_RESOLVERS.exists():
            DEFAULT_RESOLVERS.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n")
        for depth in range(1, depth_max + 1):
            next_frontier: set[str] = set()
            for base in sorted(frontier):
                out = raw_path(scan.id, f"subdomains-depth-{depth}", re.sub(r"[^a-zA-Z0-9_.-]", "_", base))
                try:
                    run_command(build_puredns_command(base, Path(wordlist.path), DEFAULT_RESOLVERS, out), timeout=1800)
                    record_raw(db, scan.id, f"subdomains-depth-{depth}", "puredns", out)
                    for name in out.read_text(errors="ignore").splitlines():
                        if name and name not in seen:
                            seen.add(name); next_frontier.add(name)
                        upsert_subdomain(db, target.id, scan.id, name, "puredns", depth)
                except Exception as e:
                    out.write_text(str(e)); record_raw(db, scan.id, f"subdomains-depth-{depth}", "puredns-error", out)
            for name in mutate_names(next_frontier or frontier, domain):
                if name not in seen:
                    seen.add(name); upsert_subdomain(db, target.id, scan.id, name, "mutation", depth)
            frontier = next_frontier
            db.commit()
    db.commit()
    return sorted(seen)

def run_httpx(db: Session, scan: models.Scan) -> list[str]:
    settings = load_settings()
    subs = [r.name for r in db.query(models.Subdomain).filter_by(target_id=scan.target_id).all()]
    infile = raw_path(scan.id, "httpx", "input")
    outfile = raw_path(scan.id, "httpx", "httpx", "jsonl")
    infile.write_text("\n".join(sorted(set(subs))))
    headers = settings.headers.copy()
    run_command(build_httpx_command(infile, outfile, settings.user_agent, headers, settings.proxy), timeout=1800)
    record_raw(db, scan.id, "httpx", "httpx", outfile)
    rows = parse_httpx_jsonl(outfile.read_text(errors="ignore"))
    urls = []
    for item in rows:
        if not item.get("url"):
            continue
        urls.append(item["url"])
        existing = db.query(models.HttpxResult).filter_by(scan_id=scan.id, url=item["url"]).one_or_none()
        if not existing:
            prior = db.query(models.HttpxResult).filter_by(target_id=scan.target_id, url=item["url"]).order_by(models.HttpxResult.id.asc()).first()
            db.add(models.HttpxResult(target_id=scan.target_id, scan_id=scan.id, first_seen_scan_id=prior.first_seen_scan_id if prior else scan.id, headers_sent={"User-Agent": settings.user_agent, **headers}, **item))
    db.commit()
    return urls

def run_ffuf(db: Session, scan: models.Scan, urls: list[str] | None = None) -> None:
    settings = load_settings(); config = scan.config or {}
    resolved_wordlist = resolve_ffuf_wordlist(db, config.get("dirb_wordlist_id"))
    metadata = raw_path(scan.id, "ffuf", "wordlist")
    metadata.write_text(f"Using {resolved_wordlist.source} FFUF wordlist: {resolved_wordlist.display_name}\nPath: {resolved_wordlist.path}\n", encoding="utf-8")
    record_raw(db, scan.id, "ffuf", "ffuf-wordlist", metadata)
    urls = urls or [r.url for r in db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code < 500).all()]
    for idx, url in enumerate(urls):
        out = raw_path(scan.id, "ffuf", re.sub(r"[^a-zA-Z0-9_.-]", "_", url), "json")
        try:
            run_command(build_ffuf_command(url, resolved_wordlist.path, out, config.get("extensions", ""), bool(config.get("ffuf_recursive", False)), config.get("ffuf_match_codes", "200,204,301,302,307,401,403"), config.get("ffuf_filter_size"), int(config.get("ffuf_threads", 25)), config.get("ffuf_rate"), settings.headers, settings.proxy), timeout=3600)
            record_raw(db, scan.id, "ffuf", "ffuf", out)
            for item in parse_ffuf_json(out.read_text(errors="ignore")):
                if not item.get("url"):
                    continue
                prior = db.query(models.DirbResult).filter_by(target_id=scan.target_id, url=item["url"]).order_by(models.DirbResult.id.asc()).first()
                db.add(models.DirbResult(target_id=scan.target_id, scan_id=scan.id, base_url=url, first_seen_scan_id=prior.first_seen_scan_id if prior else scan.id, headers_sent=settings.headers, **item))
            db.commit()
        except Exception as e:
            out.write_text(json.dumps({"error": str(e)})); record_raw(db, scan.id, "ffuf", "ffuf-error", out)
            raise

def run_screenshots(db: Session, scan: models.Scan) -> None:
    settings = load_settings()
    urls = [r.url for r in db.query(models.HttpxResult).filter(models.HttpxResult.scan_id == scan.id, models.HttpxResult.status_code.in_([200, 301, 302, 307, 401, 403])).all()]
    if not urls:
        return
    infile = raw_path(scan.id, "screenshots", "input")
    outdir = SCREEN_DIR / f"scan-{scan.id}"
    outdir.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(urls))
    try:
        run_command(build_gowitness_command(infile, outdir, settings.user_agent, settings.proxy), timeout=3600)
    except Exception as e:
        err = raw_path(scan.id, "screenshots", "gowitness-error")
        err.write_text(str(e)); record_raw(db, scan.id, "screenshots", "gowitness-error", err)
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
    scan.started_at = datetime.now(UTC); set_scan(db, scan, stage_only or "subdomains", 5)
    try:
        if stage_only in (None, "subdomains"):
            set_scan(db, scan, "subdomains", 10); enumerate_subdomains(db, scan)
        if stage_only in (None, "httpx"):
            set_scan(db, scan, "httpx", 40); urls = run_httpx(db, scan)
        else:
            urls = scan.config.get("subset_urls") if scan.config else None
        if (scan.config or {}).get("run_ffuf", True) and stage_only in (None, "ffuf"):
            set_scan(db, scan, "ffuf", 65); run_ffuf(db, scan, urls)
        if (scan.config or {}).get("run_screenshots", True) and stage_only in (None, "screenshots"):
            set_scan(db, scan, "screenshots", 85); run_screenshots(db, scan)
        scan.finished_at = datetime.now(UTC); set_scan(db, scan, "complete", 100, "complete")
    except Exception as e:
        scan.finished_at = datetime.now(UTC); set_scan(db, scan, "failed", scan.progress, "failed", str(e))
