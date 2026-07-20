import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'recon.db'}")
SQLITE_BUSY_TIMEOUT = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "10000"))

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False, "timeout": SQLITE_BUSY_TIMEOUT / 1000}
else:
    connect_args = {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def _sqlite_add_missing_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "dirb_results" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("dirb_results")}
    columns = {
        "normalized_path": "VARCHAR(1024)",
        "method": "VARCHAR(16) DEFAULT 'GET'",
        "content_type": "VARCHAR(255)",
        "redirect_location": "TEXT",
        "duration_ms": "INTEGER",
        "body_hash": "VARCHAR(128)",
        "confidence": "VARCHAR(32) DEFAULT 'unverified'",
        "filtered_reason": "TEXT",
    }
    with engine.begin() as conn:
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE dirb_results ADD COLUMN {name} {ddl}"))
        conn.execute(text("UPDATE dirb_results SET normalized_path = COALESCE(normalized_path, path)"))
        conn.execute(text("UPDATE dirb_results SET method = COALESCE(method, 'GET')"))
        conn.execute(text("UPDATE dirb_results SET confidence = COALESCE(confidence, 'unverified')"))


def _sqlite_create_indexes() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return
    indexes = [
        "CREATE INDEX IF NOT EXISTS ix_httpx_scan_status ON httpx_results(scan_id, status_code)",
        "CREATE INDEX IF NOT EXISTS ix_dirb_scan_conf ON dirb_results(scan_id, confidence)",
        "CREATE INDEX IF NOT EXISTS ix_dirb_scan_base ON dirb_results(scan_id, base_url)",
    ]
    with engine.begin() as conn:
        for stmt in indexes:
            conn.execute(text(stmt))


def init_db() -> None:
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _sqlite_add_missing_columns()
    _sqlite_create_indexes()
    if DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA busy_timeout=10000"))
            conn.execute(text("PRAGMA synchronous=NORMAL"))
            conn.execute(text("PRAGMA cache_size=-8000"))
            conn.execute(text("PRAGMA temp_store=MEMORY"))
            conn.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
