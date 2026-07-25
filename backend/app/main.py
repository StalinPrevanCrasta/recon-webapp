import csv
import io
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app import models
from app.db import get_db, init_db
from app.schemas import InterestingPatch, RunScanRequest, Settings, StageRerunRequest
from app.settings_store import load_settings, save_settings
from app.tasks import run_scan_task
from app.recon.pipeline import clean_domain
from app.recon.wordlists import FFUF_WORDLIST_UNAVAILABLE, ffuf_wordlist_status, resolve_ffuf_wordlist
from app.docker_logs import LOG_VIEWER_DISABLED, list_allowed_containers, stream_logs, validate_container_selection, viewer_enabled, clamp_tail

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
WORDLIST_DIR = DATA_DIR / "wordlists"
SCREEN_DIR = DATA_DIR / "screenshots"

app = FastAPI(title="Bug Bounty Recon Webapp")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    init_db()
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    SCREEN_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/screenshots", StaticFiles(directory=str(SCREEN_DIR), check_dir=False), name="screenshots")

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    return {"ok": True, "ffuf": ffuf_wordlist_status(db)}

@app.get("/api/system/logs/containers")
def docker_log_containers():
    if not viewer_enabled():
        raise HTTPException(403, LOG_VIEWER_DISABLED)
    return {"containers": list_allowed_containers()}

@app.get("/api/system/logs/stream")
def docker_log_stream(container: str = "all", tail: int = 200):
    if not viewer_enabled():
        raise HTTPException(403, LOG_VIEWER_DISABLED)
    try:
        validate_container_selection(container)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(stream_logs(container, clamp_tail(tail)), media_type="text/event-stream", headers=headers)

@app.get("/api/settings", response_model=Settings)
def get_settings():
    return load_settings()

@app.put("/api/settings", response_model=Settings)
def put_settings(settings: Settings):
    return save_settings(settings)

@app.get("/api/wordlists")
def list_wordlists(kind: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Wordlist)
    if kind:
        q = q.filter_by(kind=kind)
    return [{"id": w.id, "kind": w.kind, "name": w.name, "path": w.path} for w in q.order_by(models.Wordlist.kind, models.Wordlist.name).all()]

@app.post("/api/wordlists/{kind}")
async def upload_wordlist(kind: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if kind not in {"subdomain", "dirb"}:
        raise HTTPException(400, "kind must be subdomain or dirb")
    target_dir = WORDLIST_DIR / kind
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / Path(file.filename or "wordlist.txt").name
    content = await file.read()
    dest.write_bytes(content)
    row = models.Wordlist(kind=kind, name=dest.name, path=str(dest))
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "kind": row.kind, "name": row.name, "path": row.path}

@app.post("/api/scans/run")
def run_scan(req: RunScanRequest, db: Session = Depends(get_db)):
    if req.run_ffuf and req.ffuf_mode in {"generic", "combined"}:
        try:
            resolve_ffuf_wordlist(db, req.dirb_wordlist_id)
        except ValueError:
            raise HTTPException(status_code=422, detail=FFUF_WORDLIST_UNAVAILABLE)
    domain = clean_domain(req.domain)
    target = db.query(models.Target).filter_by(domain=domain).one_or_none()
    if not target:
        target = models.Target(domain=domain); db.add(target); db.commit(); db.refresh(target)
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config=req.model_dump())
    db.add(scan); db.commit(); db.refresh(scan)
    task = run_scan_task.delay(scan.id)
    return {"target_id": target.id, "scan_id": scan.id, "task_id": task.id}

@app.post("/api/scans/{scan_id}/rerun")
def rerun_stage(scan_id: int, req: StageRerunRequest, db: Session = Depends(get_db)):
    if req.stage == "ffuf" and req.ffuf_mode in {"generic", "combined"}:
        try:
            resolve_ffuf_wordlist(db, req.dirb_wordlist_id)
        except ValueError:
            raise HTTPException(status_code=422, detail=FFUF_WORDLIST_UNAVAILABLE)
    parent = db.get(models.Scan, scan_id)
    if not parent:
        raise HTTPException(404, "scan not found")
    config = dict(parent.config or {})
    config.update(req.model_dump())
    scan = models.Scan(target_id=parent.target_id, status="queued", stage=f"queued:{req.stage}", config=config)
    db.add(scan); db.commit(); db.refresh(scan)
    task = run_scan_task.delay(scan.id, req.stage)
    return {"scan_id": scan.id, "task_id": task.id}

@app.get("/api/scans/{scan_id}")
def scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return {"id": scan.id, "target_id": scan.target_id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error, "created_at": scan.created_at, "started_at": scan.started_at, "finished_at": scan.finished_at}

@app.get("/api/targets")
def targets(db: Session = Depends(get_db)):
    return [{"id": t.id, "domain": t.domain, "created_at": t.created_at, "scan_count": len(t.scans)} for t in db.query(models.Target).order_by(models.Target.created_at.desc()).all()]

@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    scan_ids = [row.id for row in db.query(models.Scan.id).filter_by(target_id=target_id).all()]
    deleted = {
        "targets": 1,
        "scans": len(scan_ids),
        "subdomains": db.query(models.Subdomain).filter_by(target_id=target_id).delete(synchronize_session=False),
        "ports": db.query(models.PortResult).filter_by(target_id=target_id).delete(synchronize_session=False),
        "http": db.query(models.HttpxResult).filter_by(target_id=target_id).delete(synchronize_session=False),
        "dirs": db.query(models.DirbResult).filter_by(target_id=target_id).delete(synchronize_session=False),
        "screenshots": db.query(models.Screenshot).filter_by(target_id=target_id).delete(synchronize_session=False),
        "raw": 0,
    }
    if scan_ids:
        deleted["raw"] = db.query(models.RawOutput).filter(models.RawOutput.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        db.query(models.Scan).filter(models.Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.delete(target)
    db.commit()
    return {"ok": True, "deleted": deleted}



def stage_statuses(db: Session, scan: models.Scan, subdomains: list, http: list, dirs: list, screenshots: list, raw: list) -> dict:
    raw_by_stage = {}
    for r in raw:
        raw_by_stage.setdefault(r.stage, []).append(r)
    def stage_state(stage: str, result_count: int) -> str:
        if scan.stage == stage and scan.status == "running":
            return "running"
        if any(r.tool.endswith("error") for r in raw_by_stage.get(stage, [])):
            return "partial" if result_count else "failed"
        if result_count or raw_by_stage.get(stage):
            return "complete"
        return "not_started"
    ffuf_errors = [r for r in raw_by_stage.get("ffuf", []) if r.tool == "ffuf-error"]
    ffuf_success = [r for r in raw_by_stage.get("ffuf", []) if r.tool == "ffuf"]
    return {
        "subdomains": {"status": stage_state("subdomains", len(subdomains)), "results": len(subdomains)},
        "naabu": {"status": stage_state("naabu", 0), "results": len([r for r in raw_by_stage.get("naabu", []) if r.tool == "naabu"])},
        "httpx": {"status": stage_state("httpx", len(http)), "results": len(http), "total": len(subdomains)},
        "wappalyzer": {"status": stage_state("wappalyzer", len([h for h in http if h.get("tech")])), "results": len([h for h in http if h.get("tech")]), "total": len(http)},
        "ffuf": {"status": "running" if scan.stage == "ffuf" and scan.status == "running" else "partial" if ffuf_errors and ffuf_success else "failed" if ffuf_errors else "complete" if ffuf_success or dirs else "not_started", "results": len(dirs), "successful_hosts": len(ffuf_success), "failed_hosts": len(ffuf_errors), "total": len(http)},
        "screenshots": {"status": stage_state("screenshots", len(screenshots)), "results": len(screenshots)},
    }

@app.get("/api/targets/{target_id}/results")
def results(target_id: int, scan_id: int | None = None, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    scans_q = db.query(models.Scan).filter_by(target_id=target_id).order_by(models.Scan.id.desc())
    scan = db.get(models.Scan, scan_id) if scan_id else scans_q.first()
    if not scan:
        return {"target": {"id": target.id, "domain": target.domain}, "scans": [], "subdomains": [], "http": [], "dirs": [], "screenshots": [], "raw": []}
    prev = db.query(models.Scan).filter(models.Scan.target_id == target_id, models.Scan.id < scan.id).order_by(models.Scan.id.desc()).first()
    def rowdict(row, keys):
        d = {k: getattr(row, k) for k in keys}; d["is_new"] = getattr(row, "first_seen_scan_id", scan.id) == scan.id and bool(prev); return d
    subdomains = [rowdict(r, ["id", "name", "sources", "depths", "interesting", "note"]) for r in db.query(models.Subdomain).filter_by(target_id=target_id).all()]
    ports = [rowdict(r, ["id", "host", "ip", "port", "protocol", "source"]) for r in db.query(models.PortResult).filter_by(scan_id=scan.id).all()]
    http = [rowdict(r, ["id", "url", "status_code", "title", "tech", "fingerprints", "ports", "response_size", "server", "redirect_chain", "ip", "headers_sent", "response_headers", "interesting", "note"]) for r in db.query(models.HttpxResult).filter_by(scan_id=scan.id).all()]
    dirs = [rowdict(r, ["id", "base_url", "url", "path", "normalized_path", "method", "status_code", "size", "words", "lines", "content_type", "redirect_location", "duration_ms", "body_hash", "confidence", "filtered_reason", "open_directory", "headers_sent", "interesting", "note"]) for r in db.query(models.DirbResult).filter_by(scan_id=scan.id).all()]
    screenshots = [{"id": r.id, "url": r.url, "image_path": r.image_path, "image_url": "/screenshots/" + str(Path(r.image_path).relative_to(SCREEN_DIR)).replace('\\', '/'), "tag": r.tag, "interesting": r.interesting, "note": r.note} for r in db.query(models.Screenshot).filter_by(scan_id=scan.id).all()]
    raw_rows = db.query(models.RawOutput).filter_by(scan_id=scan.id).all()
    raw = [{"id": r.id, "stage": r.stage, "tool": r.tool, "path": r.path} for r in raw_rows]
    return {
        "target": {"id": target.id, "domain": target.domain},
        "scans": [{"id": s.id, "status": s.status, "stage": s.stage, "progress": s.progress, "created_at": s.created_at} for s in scans_q.all()],
        "active_scan": {"id": scan.id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error},
        "stage_statuses": stage_statuses(db, scan, subdomains, http, dirs, screenshots, raw_rows),
        "subdomains": subdomains,
        "ports": ports,
        "http": http,
        "dirs": dirs,
        "screenshots": screenshots,
        "raw": raw,
    }


@app.get("/api/raw/{raw_id}")
def raw_output(raw_id: int, db: Session = Depends(get_db)):
    row = db.get(models.RawOutput, raw_id)
    if not row:
        raise HTTPException(404, "raw output not found")
    path = Path(row.path)
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "raw output file not found")
    content = path.read_text(errors="replace")
    return {"id": row.id, "stage": row.stage, "tool": row.tool, "path": row.path, "content": content[:200000], "truncated": len(content) > 200000}

MODEL_MAP = {"subdomains": models.Subdomain, "http": models.HttpxResult, "dirs": models.DirbResult, "screenshots": models.Screenshot}
@app.patch("/api/{kind}/{item_id}/interesting")
def mark_interesting(kind: str, item_id: int, patch: InterestingPatch, db: Session = Depends(get_db)):
    model = MODEL_MAP.get(kind)
    if not model:
        raise HTTPException(404, "unknown result kind")
    row = db.get(model, item_id)
    if not row:
        raise HTTPException(404, "item not found")
    row.interesting = patch.interesting
    row.note = patch.note
    if hasattr(row, "tag") and patch.tag is not None:
        row.tag = patch.tag
    db.commit()
    return {"ok": True}

@app.get("/api/targets/{target_id}/export")
def export(target_id: int, format: str = "json", db: Session = Depends(get_db)):
    data = results(target_id, None, db)
    if format == "json":
        return data
    if format == "csv":
        buf = io.StringIO(); writer = csv.writer(buf)
        writer.writerow(["type", "value", "status", "extra"])
        for s in data["subdomains"]: writer.writerow(["subdomain", s["name"], "", ",".join(s["sources"])])
        for h in data["http"]: writer.writerow(["http", h["url"], h["status_code"], ",".join(h["tech"] or [])])
        for d in data["dirs"]: writer.writerow(["content_path", d["url"], d["status_code"], f"{d.get('confidence', '')} {d.get('size', '')}"])
        return Response(buf.getvalue(), media_type="text/csv")
    raise HTTPException(400, "format must be json or csv")
