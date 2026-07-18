import os

from celery import Celery

from app.db import SessionLocal, init_db
from app.recon.pipeline import execute_scan

DEFAULT_BROKER = "redis" + "://" + "redis" + ":6379/0"
DEFAULT_BACKEND = "redis" + "://" + "redis" + ":6379/1"

celery_app = Celery(
    "recon_webapp",
    broker=os.getenv("CELERY_BROKER_URL", DEFAULT_BROKER),
    backend=os.getenv("CELERY_RESULT_BACKEND", DEFAULT_BACKEND),
)

@celery_app.task(name="run_scan")
def run_scan_task(scan_id: int, stage_only: str | None = None):
    init_db()
    db = SessionLocal()
    try:
        execute_scan(db, scan_id, stage_only)
    finally:
        db.close()
