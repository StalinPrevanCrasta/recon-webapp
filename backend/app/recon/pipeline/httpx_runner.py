import logging

from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.paths import raw_path, record_raw
from app.recon.runner import run_command
from app.settings_store import load_settings
from app.recon.wrappers import build_httpx_command, parse_httpx_jsonl

logger = logging.getLogger(__name__)


def run_httpx(db: Session, scan: models.Scan) -> list[str]:
    settings = load_settings()
    subs = [r.name for r in db.query(models.Subdomain).filter_by(target_id=scan.target_id).all()]
    infile = raw_path(scan.id, "httpx", "input")
    outfile = raw_path(scan.id, "httpx", "httpx", "jsonl")

    # Ensure the output directory exists before any file operations
    outfile.parent.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(sorted(set(subs))))

    if not subs:
        outfile.write_text("")
        record_raw(db, scan.id, "httpx", "httpx", outfile)
        return []

    headers = settings.headers.copy()

    # Pre-create the output file so it exists even if httpx fails
    outfile.write_text("")
    try:
        run_command(
            build_httpx_command(infile, outfile, settings.user_agent, headers, settings.proxy),
            timeout=1800, scan_id=scan.id,
        )
    except Exception as exc:
        logger.warning("httpx command failed: %s", exc)

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
            prior = db.query(models.HttpxResult).filter_by(
                target_id=scan.target_id, url=url,
            ).order_by(models.HttpxResult.id.asc()).first()
            prior_map[url] = prior.first_seen_scan_id if prior else scan.id
        to_add.append(models.HttpxResult(
            target_id=scan.target_id, scan_id=scan.id,
            first_seen_scan_id=prior_map[url],
            headers_sent={"User-Agent": settings.user_agent, **headers}, **item,
        ))

    for obj in to_add:
        db.add(obj)
    db.commit()
    return urls
