import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.constants import RAW_DIR


def raw_path(scan_id: int, stage: str, tool: str, suffix: str = "txt") -> Path:
    path = RAW_DIR / f"scan-{scan_id}" / stage / f"{tool}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def record_raw(db: Session, scan_id: int, stage: str, tool: str, path: Path) -> None:
    db.add(models.RawOutput(scan_id=scan_id, stage=stage, tool=tool, path=str(path)))
    db.commit()


def batch_record_raw(db: Session, scan_id: int, records: list[tuple[str, str, Path]]) -> None:
    for stage, tool, path in records:
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
