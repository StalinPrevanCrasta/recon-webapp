from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.ffuf_runner import run_ffuf
from app.recon.pipeline.httpx_runner import run_httpx
from app.recon.pipeline.paths import clear_scan_raw
from app.recon.pipeline.screenshots import run_screenshots
from app.recon.pipeline.subdomains import enumerate_subdomains

# Progress values for each scan stage
PROGRESS_STARTED = 5
PROGRESS_SUBDOMAINS = 10
PROGRESS_HTTPX = 40
PROGRESS_FFUF = 65
PROGRESS_SCREENSHOTS = 85
PROGRESS_DONE = 100


def set_scan(
    db: Session, scan: models.Scan,
    stage: str, progress: int,
    status: str = "running", error: str | None = None,
) -> None:
    scan.stage = stage
    scan.progress = progress
    scan.status = status
    if error:
        scan.error = error
    db.commit()


def execute_scan(db: Session, scan_id: int, stage_only: str | None = None) -> None:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        return

    clear_scan_raw(db, scan_id, stage_only)
    scan.started_at = datetime.now(UTC)
    set_scan(db, scan, stage_only or "subdomains", PROGRESS_STARTED)

    try:
        ffuf_stats = None
        urls: list[str] | None = None

        if stage_only in (None, "subdomains"):
            set_scan(db, scan, "subdomains", PROGRESS_SUBDOMAINS)
            enumerate_subdomains(db, scan)

        if stage_only in (None, "httpx"):
            set_scan(db, scan, "httpx", PROGRESS_HTTPX)
            urls = run_httpx(db, scan)
        elif scan.config:
            urls = scan.config.get("subset_urls")

        run_ffuf_enabled = (scan.config or {}).get("run_ffuf", True)
        if run_ffuf_enabled and stage_only in (None, "ffuf"):
            set_scan(db, scan, "ffuf", PROGRESS_FFUF)
            ffuf_stats = run_ffuf(db, scan, urls)

        run_screenshots_enabled = (scan.config or {}).get("run_screenshots", True)
        if run_screenshots_enabled and stage_only in (None, "screenshots"):
            set_scan(db, scan, "screenshots", PROGRESS_SCREENSHOTS)
            run_screenshots(db, scan)

        scan.finished_at = datetime.now(UTC)
        if ffuf_stats and ffuf_stats.get("failed_hosts"):
            error = (
                f"FFUF had {ffuf_stats['failed_hosts']} host failure(s); "
                f"{ffuf_stats.get('successful_hosts', 0)} host(s) completed."
            )
            set_scan(db, scan, "partial", PROGRESS_DONE, "partial", error)
        else:
            set_scan(db, scan, "complete", PROGRESS_DONE, "complete")

    except Exception as e:
        db.rollback()
        scan = db.get(models.Scan, scan_id)
        if scan:
            progress = scan.progress or 0
            scan.finished_at = datetime.now(UTC)
            set_scan(db, scan, "failed", progress, "failed", str(e))
