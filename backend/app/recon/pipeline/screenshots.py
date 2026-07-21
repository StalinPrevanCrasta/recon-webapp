from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.constants import SCREEN_DIR
from app.recon.pipeline.paths import raw_path, record_raw
from app.recon.runner import run_command
from app.settings_store import load_settings
from app.recon.wrappers import build_gowitness_command


def run_screenshots(db: Session, scan: models.Scan) -> None:
    settings = load_settings()
    urls = [
        r.url for r in db.query(models.HttpxResult).filter(
            models.HttpxResult.scan_id == scan.id,
            models.HttpxResult.status_code.in_([200, 301, 302, 307, 401, 403]),
        ).all()
    ]
    if not urls:
        return

    infile = raw_path(scan.id, "screenshots", "input")
    outdir = SCREEN_DIR / f"scan-{scan.id}"
    outdir.mkdir(parents=True, exist_ok=True)
    infile.write_text("\n".join(urls))

    try:
        run_command(
            build_gowitness_command(infile, outdir, settings.user_agent, settings.proxy),
            timeout=3600, scan_id=scan.id,
        )
    except Exception as e:
        err = raw_path(scan.id, "screenshots", "gowitness-error")
        err.write_text(str(e))
        record_raw(db, scan.id, "screenshots", "gowitness-error", err)
        raise

    images = list(outdir.glob("*.png")) + list(outdir.glob("*.jpg")) + list(outdir.glob("*.jpeg"))
    to_add = []
    for image in images:
        stem = image.stem.replace("_", "://", 1) if "_" in image.stem else image.stem
        to_add.append(models.Screenshot(
            target_id=scan.target_id, scan_id=scan.id,
            url=stem, image_path=str(image),
        ))
    for obj in to_add:
        db.add(obj)
    db.commit()
