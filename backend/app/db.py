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
        if "parameter_results" not in tables:
            conn.execute(text("""
                CREATE TABLE parameter_results (
                    id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    source_url VARCHAR(2048) NOT NULL,
                    base_url VARCHAR(2048),
                    param VARCHAR(512) NOT NULL,
                    sample_value TEXT,
                    method VARCHAR(16) DEFAULT 'GET' NOT NULL,
                    source VARCHAR(64) NOT NULL,
                    suspicious BOOLEAN DEFAULT 0 NOT NULL,
                    reason TEXT,
                    first_seen_scan_id INTEGER NOT NULL,
                    interesting BOOLEAN DEFAULT 0 NOT NULL,
                    note TEXT,
                    PRIMARY KEY (id),
                    FOREIGN KEY(target_id) REFERENCES targets (id),
                    FOREIGN KEY(scan_id) REFERENCES scans (id),
                    CONSTRAINT uq_scan_param_source_method UNIQUE (scan_id, source_url, param, method)
                )
            """))
            conn.execute(text("CREATE INDEX ix_parameter_results_target_id ON parameter_results (target_id)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_scan_id ON parameter_results (scan_id)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_source_url ON parameter_results (source_url)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_base_url ON parameter_results (base_url)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_param ON parameter_results (param)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_method ON parameter_results (method)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_source ON parameter_results (source)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_suspicious ON parameter_results (suspicious)"))
            conn.execute(text("CREATE INDEX ix_parameter_results_first_seen_scan_id ON parameter_results (first_seen_scan_id)"))
        if "js_findings" not in tables:
            conn.execute(text("""
                CREATE TABLE js_findings (
                    id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    page_url VARCHAR(2048),
                    source_url VARCHAR(2048) NOT NULL,
                    file_path VARCHAR(2048),
                    finding_type VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) DEFAULT 'info' NOT NULL,
                    indicator VARCHAR(1024) NOT NULL,
                    evidence TEXT,
                    line INTEGER,
                    column INTEGER,
                    confidence VARCHAR(32) DEFAULT 'heuristic' NOT NULL,
                    tags JSON DEFAULT '[]' NOT NULL,
                    first_seen_scan_id INTEGER NOT NULL,
                    interesting BOOLEAN DEFAULT 0 NOT NULL,
                    note TEXT,
                    PRIMARY KEY (id),
                    FOREIGN KEY(target_id) REFERENCES targets (id),
                    FOREIGN KEY(scan_id) REFERENCES scans (id),
                    CONSTRAINT uq_scan_js_finding UNIQUE (scan_id, source_url, finding_type, indicator)
                )
            """))
            conn.execute(text("CREATE INDEX ix_js_findings_target_id ON js_findings (target_id)"))
            conn.execute(text("CREATE INDEX ix_js_findings_scan_id ON js_findings (scan_id)"))
            conn.execute(text("CREATE INDEX ix_js_findings_page_url ON js_findings (page_url)"))
            conn.execute(text("CREATE INDEX ix_js_findings_source_url ON js_findings (source_url)"))
            conn.execute(text("CREATE INDEX ix_js_findings_finding_type ON js_findings (finding_type)"))
            conn.execute(text("CREATE INDEX ix_js_findings_severity ON js_findings (severity)"))
            conn.execute(text("CREATE INDEX ix_js_findings_indicator ON js_findings (indicator)"))
            conn.execute(text("CREATE INDEX ix_js_findings_confidence ON js_findings (confidence)"))
            conn.execute(text("CREATE INDEX ix_js_findings_first_seen_scan_id ON js_findings (first_seen_scan_id)"))
        if "nuclei_findings" not in tables:
            conn.execute(text("""
                CREATE TABLE nuclei_findings (
                    id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    template_id VARCHAR(512) NOT NULL,
                    template_name TEXT,
                    severity VARCHAR(32) NOT NULL,
                    matched_at VARCHAR(2048) NOT NULL,
                    host VARCHAR(512),
                    ip VARCHAR(128),
                    matcher_name VARCHAR(255),
                    type VARCHAR(64),
                    description TEXT,
                    extracted_results JSON DEFAULT '[]' NOT NULL,
                    references JSON DEFAULT '[]' NOT NULL,
                    tags JSON DEFAULT '[]' NOT NULL,
                    raw JSON DEFAULT '{}' NOT NULL,
                    first_seen_scan_id INTEGER NOT NULL,
                    interesting BOOLEAN DEFAULT 0 NOT NULL,
                    note TEXT,
                    PRIMARY KEY (id),
                    FOREIGN KEY(target_id) REFERENCES targets (id),
                    FOREIGN KEY(scan_id) REFERENCES scans (id),
                    CONSTRAINT uq_scan_nuclei_template_match UNIQUE (scan_id, template_id, matched_at)
                )
            """))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_target_id ON nuclei_findings (target_id)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_scan_id ON nuclei_findings (scan_id)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_template_id ON nuclei_findings (template_id)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_severity ON nuclei_findings (severity)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_matched_at ON nuclei_findings (matched_at)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_host ON nuclei_findings (host)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_ip ON nuclei_findings (ip)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_type ON nuclei_findings (type)"))
            conn.execute(text("CREATE INDEX ix_nuclei_findings_first_seen_scan_id ON nuclei_findings (first_seen_scan_id)"))


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
