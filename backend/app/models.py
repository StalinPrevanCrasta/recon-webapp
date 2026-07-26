from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db import Base

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    target: Mapped[Target] = relationship(back_populates="scans")

class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("target_id", "name", name="uq_target_subdomain"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    depths: Mapped[list[int]] = mapped_column(JSON, default=list)
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class HttpxResult(Base):
    __tablename__ = "httpx_results"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_url"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(String(1024), index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, index=True)
    title: Mapped[str | None] = mapped_column(Text)
    tech: Mapped[list[str]] = mapped_column(JSON, default=list)
    fingerprints: Mapped[list[str]] = mapped_column(JSON, default=list)
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    ports: Mapped[list[int]] = mapped_column(JSON, default=list)
    response_size: Mapped[int | None] = mapped_column(Integer)
    server: Mapped[str | None] = mapped_column(String(255))
    redirect_chain: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(128), index=True)
    headers_sent: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)

class PortResult(Base):
    __tablename__ = "port_results"
    __table_args__ = (UniqueConstraint("scan_id", "host", "port", "protocol", name="uq_scan_host_port_proto"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    host: Mapped[str] = mapped_column(String(512), index=True)
    ip: Mapped[str | None] = mapped_column(String(128), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(32), default="tcp", index=True)
    source: Mapped[str] = mapped_column(String(64), default="naabu")
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)

class DirbResult(Base):
    __tablename__ = "dirb_results"
    __table_args__ = (
        UniqueConstraint("scan_id", "url", name="uq_scan_dir_url"),
        UniqueConstraint("scan_id", "base_url", "normalized_path", "method", name="uq_scan_base_path_method"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    base_url: Mapped[str] = mapped_column(String(1024), index=True)
    url: Mapped[str] = mapped_column(String(2048), index=True)
    path: Mapped[str | None] = mapped_column(String(1024))
    normalized_path: Mapped[str | None] = mapped_column(String(1024), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer, index=True)
    size: Mapped[int | None] = mapped_column(Integer)
    words: Mapped[int | None] = mapped_column(Integer)
    lines: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    redirect_location: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    body_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    confidence: Mapped[str] = mapped_column(String(32), default="unverified", index=True)
    filtered_reason: Mapped[str | None] = mapped_column(Text)
    open_directory: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    headers_sent: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)

class Screenshot(Base):
    __tablename__ = "screenshots"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_screenshot_url"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(String(2048), index=True)
    image_path: Mapped[str] = mapped_column(String(2048))
    thumb_path: Mapped[str | None] = mapped_column(String(2048))
    tag: Mapped[str | None] = mapped_column(String(128), index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)

class ParameterResult(Base):
    __tablename__ = "parameter_results"
    __table_args__ = (UniqueConstraint("scan_id", "source_url", "param", "method", name="uq_scan_param_source_method"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    source_url: Mapped[str] = mapped_column(String(2048), index=True)
    base_url: Mapped[str | None] = mapped_column(String(2048), index=True)
    param: Mapped[str] = mapped_column(String(512), index=True)
    sample_value: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16), default="GET", index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    reason: Mapped[str | None] = mapped_column(Text)
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)

class JsFinding(Base):
    __tablename__ = "js_findings"
    __table_args__ = (UniqueConstraint("scan_id", "source_url", "finding_type", "indicator", name="uq_scan_js_finding"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    page_url: Mapped[str | None] = mapped_column(String(2048), index=True)
    source_url: Mapped[str] = mapped_column(String(2048), index=True)
    file_path: Mapped[str | None] = mapped_column(String(2048))
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="info", index=True)
    indicator: Mapped[str] = mapped_column(String(1024), index=True)
    evidence: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    column: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(32), default="heuristic", index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_scan_id: Mapped[int] = mapped_column(Integer, index=True)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)

class RawOutput(Base):
    __tablename__ = "raw_outputs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    stage: Mapped[str] = mapped_column(String(64), index=True)
    tool: Mapped[str] = mapped_column(String(64), index=True)
    path: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Wordlist(Base):
    __tablename__ = "wordlists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # subdomain or dirb
    name: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(2048), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
