import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'recon.db'}")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
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
    tables = set(inspector.get_table_names())
    existing_dirb = {col["name"] for col in inspector.get_columns("dirb_results")}
    dirb_columns = {
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
        for name, ddl in dirb_columns.items():
            if name not in existing_dirb:
                conn.execute(text(f"ALTER TABLE dirb_results ADD COLUMN {name} {ddl}"))
        conn.execute(text("UPDATE dirb_results SET normalized_path = COALESCE(normalized_path, path)"))
        conn.execute(text("UPDATE dirb_results SET method = COALESCE(method, 'GET')"))
        conn.execute(text("UPDATE dirb_results SET confidence = COALESCE(confidence, 'unverified')"))
        if "httpx_results" in tables:
            existing_httpx = {col["name"] for col in inspector.get_columns("httpx_results")}
            httpx_columns = {
                "fingerprints": "JSON DEFAULT '[]'",
                "response_headers": "JSON DEFAULT '{}'",
                "ports": "JSON DEFAULT '[]'",
            }
            for name, ddl in httpx_columns.items():
                if name not in existing_httpx:
                    conn.execute(text(f"ALTER TABLE httpx_results ADD COLUMN {name} {ddl}"))
        if "port_results" not in tables:
            conn.execute(text("""
                CREATE TABLE port_results (
                    id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    host VARCHAR(512) NOT NULL,
                    ip VARCHAR(128),
                    port INTEGER NOT NULL,
                    protocol VARCHAR(32) DEFAULT 'tcp' NOT NULL,
                    source VARCHAR(64) DEFAULT 'naabu' NOT NULL,
                    first_seen_scan_id INTEGER NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY(target_id) REFERENCES targets (id),
                    FOREIGN KEY(scan_id) REFERENCES scans (id),
                    CONSTRAINT uq_scan_host_port_proto UNIQUE (scan_id, host, port, protocol)
                )
            """))
            conn.execute(text("CREATE INDEX ix_port_results_target_id ON port_results (target_id)"))
            conn.execute(text("CREATE INDEX ix_port_results_scan_id ON port_results (scan_id)"))
            conn.execute(text("CREATE INDEX ix_port_results_host ON port_results (host)"))
            conn.execute(text("CREATE INDEX ix_port_results_ip ON port_results (ip)"))
            conn.execute(text("CREATE INDEX ix_port_results_port ON port_results (port)"))
            conn.execute(text("CREATE INDEX ix_port_results_protocol ON port_results (protocol)"))
            conn.execute(text("CREATE INDEX ix_port_results_first_seen_scan_id ON port_results (first_seen_scan_id)"))


def init_db() -> None:
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _sqlite_add_missing_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
