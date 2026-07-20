import os

from celery import Celery

from app.db import SessionLocal, init_db
from app.recon.pipeline import execute_scan

DEFAULT_BROKER = "redis" + "://" + "redis" + ":6379/0"
DEFAULT_BACKEND = "redis" + "://" + "redis" + ":6379/1"

CELERY_TASK_SOFT_TIME_LIMIT = int(os.getenv("CELERY_TASK_SOFT_TIME_LIMIT", "7200"))
CELERY_TASK_TIME_LIMIT = int(os.getenv("CELERY_TASK_TIME_LIMIT", "7800"))

celery_app = Celery(
    "recon_webapp",
    broker=os.getenv("CELERY_BROKER_URL", DEFAULT_BROKER),
    backend=os.getenv("CELERY_RESULT_BACKEND", DEFAULT_BACKEND),
)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=CELERY_TASK_SOFT_TIME_LIMIT,
    task_time_limit=CELERY_TASK_TIME_LIMIT,
    task_track_started=True,
    result_expires=os.getenv("CELERY_RESULT_EXPIRES", "86400"),
    worker_prefetch_multiplier=1,
    task_routes={
        "run_scan": {"queue": "scan"},
        "run_scan_stage": {"queue": "scan"},
    },
)

@celery_app.task(name="run_scan")
def run_scan_task(scan_id: int, stage_only: str | None = None):
    init_db()
    db = SessionLocal()
    try:
        execute_scan(db, scan_id, stage_only)
    finally:
        db.close()
