import csv
import base64
import asyncio
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import httpx as pyhttpx
import websockets
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import models
from app.db import get_db, init_db
from app.schemas import (ArjunRunRequest, InterestingPatch, PlaygroundRequestSend, PlaygroundToolRequest,
    RunScanRequest, Settings, StageRerunRequest, ArtifactParseRequest, EndpointInventoryCompareRequest,
    AuthorizationMatrixRequest, PropertyCompareRequest, UploadAnalysisRequest, PayloadCampaignRequest,
    WebSocketCompareRequest)
from app.security_intel import (analyze_upload, compare_authorization_cases, compare_endpoint_inventory,
    compare_properties, find_object_identifiers, parse_artifact)
from app.settings_store import load_settings, save_settings
from app.tasks import run_scan_task
from app.recon.pipeline import clean_domain
from app.recon.normalization import canonical_asset_key, normalize_indicator, normalize_path_pattern
from app.recon.runner import CommandError, cancel_scan, run_command
from app.recon.wrappers import build_arjun_command, parse_arjun_json
from app.recon.wordlists import FFUF_WORDLIST_UNAVAILABLE, ffuf_wordlist_status, resolve_ffuf_wordlist
from app.docker_logs import LOG_VIEWER_DISABLED, list_allowed_containers, stream_logs, validate_container_selection, viewer_enabled, clamp_tail

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
WORDLIST_DIR = DATA_DIR / "wordlists"
SCREEN_DIR = DATA_DIR / "screenshots"
PLAYGROUND_DIR = DATA_DIR / "playground"
PLAYGROUND_BODY_LIMIT = 200000
SENSITIVE_PLAYGROUND_HEADERS = {"authorization", "cookie", "x-api-key", "proxy-authorization"}

app = FastAPI(title="Bug Bounty Recon Webapp")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    init_db()
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    SCREEN_DIR.mkdir(parents=True, exist_ok=True)
    PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)

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
def docker_log_stream(container: str = "all", tail: str = "1000"):
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


def _validate_playground_url(url: str) -> str:
    normalized = str(url or "").strip()
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, "Playground URL must be an absolute http or https URL.")
    return normalized


def _read_raw_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


def _raw_meta(raw_rows: list[models.RawOutput], stage: str, tool: str) -> dict:
    for row in raw_rows:
        if row.stage == stage and row.tool == tool:
            return _read_raw_json(row.path)
    return {}


def recover_stale_scan(db: Session, scan: models.Scan) -> None:
    if not scan or scan.status not in {"running", "queued", "stopping"}:
        return
    stale_minutes = int((scan.config or {}).get("stale_scan_minutes", 30))
    scan_dir = DATA_DIR / "raw" / f"scan-{scan.id}"
    latest_ts = scan.started_at or scan.created_at
    stale_stage = scan.stage
    if scan_dir.exists():
        for path in scan_dir.rglob("*"):
            try:
                if path.is_file():
                    latest_ts = max(latest_ts, datetime.fromtimestamp(path.stat().st_mtime))
            except OSError:
                pass
    if datetime.utcnow() - latest_ts < timedelta(minutes=stale_minutes):
        return
    scan.status = "partial" if scan.progress and scan.progress >= 50 else "failed"
    scan.stage = "stale"
    scan.finished_at = datetime.now(UTC)
    scan.error = f"Scan marked stale after {stale_minutes} minute(s) without raw-output activity during {stale_stage}."
    db.commit()


def _playground_headers(headers: dict[str, str] | None, body_type: str = "raw") -> dict[str, str]:
    cleaned = {str(k).strip(): str(v) for k, v in (headers or {}).items() if str(k).strip()}
    lower_keys = {k.lower() for k in cleaned}
    if body_type == "json" and "content-type" not in lower_keys:
        cleaned["Content-Type"] = "application/json"
    if body_type == "form" and "content-type" not in lower_keys:
        cleaned["Content-Type"] = "application/x-www-form-urlencoded"
    return cleaned


def _mask_playground_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: ("••••••••" if key.lower() in SENSITIVE_PLAYGROUND_HEADERS and value else value) for key, value in (headers or {}).items()}


def _body_parameter_names(body: str | None, body_type: str) -> list[str]:
    if not body or body_type in {"none", ""}:
        return []
    if body_type == "json":
        try:
            parsed = json.loads(body)
        except Exception:
            return []
        if isinstance(parsed, dict):
            return [str(k) for k in parsed.keys()]
        return []
    if body_type == "form":
        return [key for key, _ in parse_qsl(body, keep_blank_values=True)]
    return []


def _testable_parameters(req: PlaygroundToolRequest) -> list[dict]:
    parsed = urlparse(req.url)
    params = [{"name": key, "location": "GET"} for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    body_location = "JSON" if req.body_type == "json" else "POST"
    params.extend({"name": key, "location": body_location} for key in _body_parameter_names(req.body, req.body_type))
    seen = set()
    unique = []
    for item in params:
        key = (item["location"], item["name"])
        if item["name"] and key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _is_static_asset(url: str) -> bool:
    suffix = Path(urlparse(url).path.lower()).suffix
    return suffix in {".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".mp4", ".mp3", ".avi", ".mov"}


def _content_type(headers: dict[str, str]) -> str | None:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value
    return None


def _js_finder(row: dict) -> str:
    tags = {str(tag).lower() for tag in (row.get("tags") or [])}
    finding_type = str(row.get("finding_type") or "").lower()
    if "trufflehog" in tags or finding_type.startswith("trufflehog"):
        return "TruffleHog"
    return "Custom JS analyzer"


def _row_playground_request(row: models.PlaygroundRequest) -> dict:
    return {
        "id": row.id,
        "target_id": row.target_id,
        "method": row.method,
        "url": row.url,
        "request_headers": row.request_headers or {},
        "request_body": row.request_body or "",
        "status_code": row.status_code,
        "response_headers": row.response_headers or {},
        "response_body": row.response_body or "",
        "response_size": row.response_size,
        "duration_ms": row.duration_ms,
        "error": row.error,
        "interesting": row.interesting,
        "note": row.note,
        "created_at": row.created_at,
    }


@app.get("/api/playground/history")
def playground_history(limit: int = 30, target_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(models.PlaygroundRequest)
    if target_id:
        query = query.filter_by(target_id=target_id)
    rows = query.order_by(models.PlaygroundRequest.created_at.desc()).limit(max(1, min(limit, 200))).all()
    return {"items": [_row_playground_request(row) for row in rows]}


@app.post("/api/playground/request")
def playground_send(req: PlaygroundRequestSend, db: Session = Depends(get_db)):
    url = _validate_playground_url(req.url)
    method = req.method.strip().upper() or "GET"
    body_type = (req.body_type or "raw").lower()
    headers = _playground_headers(req.headers, body_type)
    started = time.monotonic()
    status_code = None
    response_headers = {}
    response_body = ""
    response_size = 0
    error = None
    try:
        response = pyhttpx.request(
            method,
            url,
            headers=headers,
            content=req.body.encode("utf-8") if req.body is not None else None,
            follow_redirects=req.follow_redirects,
            timeout=req.timeout,
        )
        status_code = response.status_code
        response_headers = dict(response.headers)
        response_size = len(response.content or b"")
        response_body = response.text[:PLAYGROUND_BODY_LIMIT]
        final_url = str(response.url)
        redirect_count = len(response.history)
    except Exception as exc:
        error = str(exc)
        final_url = url
        redirect_count = 0
    duration_ms = int((time.monotonic() - started) * 1000)
    payload = {
        "target_id": req.target_id,
        "method": method,
        "url": url,
        "request_headers": headers,
        "request_body": req.body or "",
        "status_code": status_code,
        "response_headers": response_headers,
        "response_body": response_body,
        "response_size": response_size,
        "duration_ms": duration_ms,
        "error": error,
    }
    row = None
    if req.save:
        row = models.PlaygroundRequest(**payload)
        db.add(row)
        db.commit()
        db.refresh(row)
    item = _row_playground_request(row) if row else {"id": None, **payload}
    item.update({"final_url": final_url, "redirect_count": redirect_count, "content_type": _content_type(response_headers), "truncated": response_size > len(response_body.encode("utf-8"))})
    return {"item": item, "truncated": item["truncated"]}


@app.patch("/api/playground/history/{request_id}")
def playground_patch_history(request_id: int, patch: InterestingPatch, db: Session = Depends(get_db)):
    row = db.get(models.PlaygroundRequest, request_id)
    if not row:
        raise HTTPException(404, "playground request not found")
    row.interesting = patch.interesting
    row.note = patch.note
    db.commit()
    return {"ok": True}


def _arjun_executable() -> list[str] | None:
    venv_arjun = Path("/opt/venv/bin/arjun")
    if venv_arjun.exists():
        return [str(venv_arjun)]
    venv_python = Path("/opt/venv/bin/python")
    if venv_python.exists():
        return [str(venv_python), "-m", "arjun"]
    arjun = shutil.which("arjun")
    if arjun:
        return [arjun]
    python = shutil.which("python") or shutil.which("python3")
    if python:
        return [python, "-m", "arjun"]
    return None


@app.post("/api/playground/arjun")
def playground_arjun(req: PlaygroundToolRequest):
    url = _validate_playground_url(req.url)
    method = req.method.strip().upper() or "GET"
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise HTTPException(422, "Arjun supports standard HTTP methods only.")
    if _is_static_asset(url):
        raise HTTPException(422, "Arjun is disabled for obvious static assets.")
    exe = _arjun_executable()
    if not exe:
        raise HTTPException(501, "Arjun is not available in this container. Rebuild the backend image after installing requirements.")
    PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=PLAYGROUND_DIR) as td:
        work = Path(td)
        infile = work / "arjun-input.txt"
        outfile = work / "arjun.json"
        infile.write_text(url + "\n", encoding="utf-8")
        headers = _playground_headers(req.headers, req.body_type)
        methods = [m.strip().upper() for m in req.arjun_methods.split(",") if m.strip()] or [method]
        results = []
        raw_outputs = []
        for method in methods:
            cmd = build_arjun_command(infile, outfile, method, req.arjun_threads, req.arjun_request_timeout, headers, req.arjun_stable)
            cmd = exe + cmd[1:]
            try:
                stdout, stderr = run_command(cmd, timeout=req.timeout)
            except CommandError as exc:
                stdout, stderr = exc.stdout or "", exc.stderr or str(exc)
            text = outfile.read_text(errors="ignore") if outfile.exists() else stdout
            raw_outputs.append({"method": method, "stdout": stdout, "stderr": stderr, "json": text[:PLAYGROUND_BODY_LIMIT], "request": {"method": method, "headers": _mask_playground_headers(headers), "body_type": req.body_type, "body": req.body or ""}})
            results.extend(parse_arjun_json(text, f"arjun-{method.lower()}"))
            if outfile.exists():
                outfile.unlink()
        return {"url": url, "parameters": results, "raw": raw_outputs}


@app.post("/api/playground/dalfox")
def playground_dalfox(req: PlaygroundToolRequest):
    url = _validate_playground_url(req.url)
    method = req.method.strip().upper() or "GET"
    params = _testable_parameters(req)
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise HTTPException(422, "Dalfox supports GET, POST, PUT, PATCH, and DELETE requests in the Playground.")
    if not params:
        raise HTTPException(422, "No testable parameter found. Run Arjun first or add a parameter manually.")
    dalfox = shutil.which("dalfox")
    if not dalfox:
        raise HTTPException(501, "Dalfox is not available in this container. Rebuild the backend image after adding Dalfox.")
    headers = _playground_headers(req.headers, req.body_type)
    cmd = [dalfox, "url", url, "--silence", "--format", "json", "--timeout", str(req.timeout), "-X", method]
    for key, value in headers.items():
        cmd.extend(["-H", f"{key}: {value}"])
    if req.body and req.body_type != "none":
        cmd.extend(["-d", req.body])
    if req.dalfox_options:
        cmd.extend(part for part in req.dalfox_options.split() if part)
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=req.timeout + 10)
    except subprocess.TimeoutExpired as exc:
        return {"url": url, "ok": False, "error": f"Dalfox timed out after {req.timeout}s.", "stdout": (exc.stdout or "")[:PLAYGROUND_BODY_LIMIT], "stderr": (exc.stderr or "")[:PLAYGROUND_BODY_LIMIT], "findings": []}
    findings = []
    try:
        import json
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else []
        findings = parsed if isinstance(parsed, list) else parsed.get("data", []) if isinstance(parsed, dict) else []
    except Exception:
        findings = []
    return {"url": url, "ok": proc.returncode == 0, "returncode": proc.returncode, "parameters": params, "findings": findings, "stdout": proc.stdout[:PLAYGROUND_BODY_LIMIT], "stderr": proc.stderr[:PLAYGROUND_BODY_LIMIT], "request": {"method": method, "headers": _mask_playground_headers(headers), "body_type": req.body_type, "body": req.body or ""}}


@app.post("/api/security/artifacts/parse")
def security_parse_artifact(req: ArtifactParseRequest):
    try:
        return parse_artifact(req.content, req.artifact_type, req.source)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/security/endpoints/compare")
def security_compare_endpoints(req: EndpointInventoryCompareRequest):
    return compare_endpoint_inventory(req.documented, req.observed)


@app.post("/api/security/authorization/compare")
def security_compare_authorization(req: AuthorizationMatrixRequest):
    return compare_authorization_cases(req.cases)


@app.post("/api/security/graphql/matrix")
def security_graphql_matrix(req: AuthorizationMatrixRequest):
    result = compare_authorization_cases(req.cases)
    result["operation_matrix"] = [
        {"role": row.get("role"), "operation": row.get("operation"), "status": row.get("status"),
         "errors": (row.get("body") or {}).get("errors", []) if isinstance(row.get("body"), dict) else [],
         "returned_fields": row.get("fields", []), "object_identifiers": row.get("identifiers", [])}
        for row in result["matrix"]
    ]
    return result


@app.post("/api/security/objects/identify")
def security_identify_objects(payload: dict):
    return {"identifiers": find_object_identifiers(payload, location=str(payload.get("location", "body")))}


@app.post("/api/security/properties/compare")
def security_compare_property_authorization(req: PropertyCompareRequest):
    return compare_properties(req.original, req.attempted, req.response, req.read_only)


@app.post("/api/security/uploads/analyze")
def security_analyze_upload(req: UploadAnalysisRequest):
    try:
        content = base64.b64decode(req.content_base64, validate=True) if req.content_base64 else b""
    except Exception as exc:
        raise HTTPException(422, "content_base64 is not valid base64") from exc
    if len(content) > 10_000_000:
        raise HTTPException(413, "Upload sample exceeds the 10 MB analysis limit.")
    return analyze_upload(req.filename, req.declared_mime, content, req.response, req.retrieval_cases)


def _campaign_response(method: str, url: str, headers: dict, body: str, timeout: int,
                       follow_redirects: bool, proxy: str | None) -> dict:
    started = time.monotonic()
    try:
        with pyhttpx.Client(proxy=proxy, follow_redirects=follow_redirects, timeout=timeout) as client:
            response = client.request(method, url, headers=headers, content=body.encode() if body else None)
        return {"status": response.status_code, "body": response.text[:PLAYGROUND_BODY_LIMIT],
                "size": len(response.content), "duration_ms": int((time.monotonic() - started) * 1000),
                "content_type": response.headers.get("content-type", ""), "error": None}
    except Exception as exc:
        return {"status": None, "body": "", "size": 0,
                "duration_ms": int((time.monotonic() - started) * 1000), "content_type": "", "error": str(exc)}


@app.post("/api/playground/payload-campaign")
def playground_payload_campaign(req: PayloadCampaignRequest):
    marker = "{{PAYLOAD}}"
    if marker not in req.url_template and marker not in req.body_template:
        raise HTTPException(422, f"Add {marker} to the URL or body where payloads should be inserted.")
    _validate_playground_url(req.url_template.replace(marker, "baseline"))
    proxies = []
    for proxy in req.proxies:
        parsed = urlparse(proxy)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.netloc:
            raise HTTPException(422, f"Invalid proxy URL: {proxy}")
        proxies.append(proxy)
    method = req.method.upper()
    headers = _playground_headers(req.headers, req.body_type)
    baseline = _campaign_response(method, req.url_template.replace(marker, "baseline"), headers,
                                  req.body_template.replace(marker, "baseline"), req.timeout, req.follow_redirects,
                                  proxies[0] if proxies else None)
    sql_error = re.compile(r"SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL.*ERROR|SQLite.*(?:error|exception)|Unclosed quotation mark|ODBC SQL", re.I)
    baseline_sql_error = bool(sql_error.search(baseline["body"]))
    results = []
    minimum_gap = max(req.delay_ms / 1000, 1 / req.rate_limit_per_second)
    last_started = 0.0
    for index, payload in enumerate(req.payloads):
        wait_for = minimum_gap - (time.monotonic() - last_started)
        if wait_for > 0:
            time.sleep(wait_for)
        last_started = time.monotonic()
        proxy = proxies[index % len(proxies)] if proxies else None
        url = req.url_template.replace(marker, payload)
        body = req.body_template.replace(marker, payload)
        result = _campaign_response(method, url, headers, body, req.timeout, req.follow_redirects, proxy)
        reflected = bool(payload and payload in result["body"] and payload not in baseline["body"])
        new_sql_error = bool(sql_error.search(result["body"])) and not baseline_sql_error
        timed = result["duration_ms"] >= baseline["duration_ms"] + req.time_threshold_ms
        anomaly = (result["status"] != baseline["status"] or abs(result["size"] - baseline["size"]) > max(100, baseline["size"] * .25))
        evidence = []
        if reflected: evidence.append("payload reflected verbatim")
        if new_sql_error: evidence.append("new database error signature")
        if timed: evidence.append(f"response delayed {result['duration_ms'] - baseline['duration_ms']} ms over baseline")
        if anomaly: evidence.append("status or response-size anomaly")
        found = reflected or new_sql_error or timed
        results.append({"index": index + 1, "payload": payload, "found": found,
                        "confidence": "high" if new_sql_error else "medium" if found else "none",
                        "evidence": evidence, "status": result["status"], "size": result["size"],
                        "duration_ms": result["duration_ms"], "error": result["error"],
                        "response_excerpt": result["body"][:500], "proxy_slot": index % len(proxies) if proxies else None})
    return {"baseline": {k: v for k, v in baseline.items() if k != "body"}, "results": results,
            "summary": {"tested": len(results), "found": sum(1 for row in results if row["found"]),
                        "errors": sum(1 for row in results if row["error"]), "proxy_rotation": bool(proxies)}}


async def _websocket_session(url: str, session, timeout: int) -> dict:
    received = []
    try:
        async with websockets.connect(url, additional_headers=session.headers, open_timeout=timeout,
                                      close_timeout=2) as socket:
            for message in session.messages:
                await socket.send(message)
                try:
                    received.append(await asyncio.wait_for(socket.recv(), timeout=timeout))
                except TimeoutError:
                    received.append(None)
        return {"label": session.label, "messages": session.messages, "received": received, "error": None}
    except Exception as exc:
        return {"label": session.label, "messages": session.messages, "received": received, "error": str(exc)}


@app.post("/api/security/websockets/compare")
async def security_compare_websockets(req: WebSocketCompareRequest):
    parsed = urlparse(req.url)
    if parsed.scheme not in {"ws", "wss"} or not parsed.netloc:
        raise HTTPException(422, "WebSocket URL must use ws:// or wss://.")
    sessions = await asyncio.gather(*[_websocket_session(req.url, session, req.timeout) for session in req.sessions])
    same_responses = len(sessions) == 2 and sessions[0]["received"] == sessions[1]["received"]
    return {"sessions": sessions, "same_responses": same_responses,
            "authorization_signal": "review identical cross-session access" if same_responses else "responses differ"}

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
    config["parent_scan_id"] = parent.id
    config["focused_stage"] = req.stage
    scan = models.Scan(target_id=parent.target_id, status="queued", stage=f"queued:{req.stage}", config=config)
    db.add(scan); db.commit(); db.refresh(scan)
    task = run_scan_task.delay(scan.id, req.stage)
    return {"scan_id": scan.id, "task_id": task.id}

@app.post("/api/scans/{scan_id}/arjun")
def run_arjun_for_scan(scan_id: int, req: ArjunRunRequest, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status in {"queued", "running", "stopping"}:
        raise HTTPException(409, "scan is already running")
    config = dict(scan.config or {})
    config.update(req.model_dump())
    config["run_arjun"] = True
    scan.config = config
    scan.status = "queued"
    scan.stage = "queued:arjun"
    scan.progress = max(scan.progress or 0, 80)
    scan.error = None
    db.query(models.ParameterResult).filter(
        models.ParameterResult.scan_id == scan.id,
        models.ParameterResult.source.like("arjun-%"),
    ).delete(synchronize_session=False)
    db.commit()
    task = run_scan_task.delay(scan.id, "arjun")
    return {"scan_id": scan.id, "task_id": task.id}

@app.get("/api/scans/{scan_id}")
def scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    recover_stale_scan(db, scan)
    db.refresh(scan)
    return {"id": scan.id, "target_id": scan.target_id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error, "created_at": scan.created_at, "started_at": scan.started_at, "finished_at": scan.finished_at}

@app.post("/api/scans/{scan_id}/stop")
def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.status not in {"queued", "running", "stopping"}:
        return {"ok": True, "killed": 0, "scan": {"id": scan.id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error}}

    previous_status = scan.status
    scan.status = "stopping"
    scan.error = "Scan stop requested by user"
    db.commit()
    killed = cancel_scan(scan_id)
    db.refresh(scan)
    if previous_status == "queued" and killed == 0:
        scan.status = "stopped"
        scan.stage = "stopped"
        scan.finished_at = datetime.now(UTC)
        db.commit()
        db.refresh(scan)
    return {"ok": True, "killed": killed, "scan": {"id": scan.id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error}}

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
        "parameters": db.query(models.ParameterResult).filter_by(target_id=target_id).delete(synchronize_session=False),
        "js": db.query(models.JsFinding).filter_by(target_id=target_id).delete(synchronize_session=False),
        "nuclei": db.query(models.NucleiFinding).filter_by(target_id=target_id).delete(synchronize_session=False),
        "screenshots": db.query(models.Screenshot).filter_by(target_id=target_id).delete(synchronize_session=False),
        "playground": db.query(models.PlaygroundRequest).filter_by(target_id=target_id).delete(synchronize_session=False),
        "raw": 0,
    }
    if scan_ids:
        deleted["raw"] = db.query(models.RawOutput).filter(models.RawOutput.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        db.query(models.Scan).filter(models.Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.delete(target)
    db.commit()
    return {"ok": True, "deleted": deleted}


@app.delete("/api/targets/{target_id}/subdomains/cache")
def clear_subdomain_cache(target_id: int, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    deleted = db.query(models.Subdomain).filter_by(target_id=target_id).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": {"subdomains": deleted}}



def stage_statuses(db: Session, scan: models.Scan, subdomains: list, http: list, dirs: list, parameters: list, arjun: list, js_findings: list, nuclei_findings: list, screenshots: list, raw: list) -> dict:
    raw_by_stage = {}
    for r in raw:
        raw_by_stage.setdefault(r.stage, []).append(r)
    def stage_state(stage: str, result_count: int) -> str:
        if scan.status == "stopping":
            return "running" if scan.stage == stage else "not_started"
        if scan.stage == stage and scan.status == "running":
            return "running"
        if any(r.tool.endswith("error") for r in raw_by_stage.get(stage, [])):
            return "partial" if result_count else "failed"
        if result_count or raw_by_stage.get(stage):
            return "complete"
        return "not_started"
    ffuf_errors = [r for r in raw_by_stage.get("ffuf", []) if r.tool == "ffuf-error"]
    ffuf_success = [r for r in raw_by_stage.get("ffuf", []) if r.tool == "ffuf"]
    ffuf_summary = _raw_meta(raw, "ffuf", "ffuf-summary")
    parameter_summary = _raw_meta(raw, "parameters", "parameters-summary")
    screenshot_summary = _raw_meta(raw, "screenshots", "screenshots-summary")
    new_subdomain_count = len([s for s in subdomains if s.get("is_new")])
    cached_subdomain_count = max(0, len(subdomains) - new_subdomain_count)
    return {
        "subdomains": {"status": stage_state("subdomains", len(subdomains)), "results": len(subdomains), "new": new_subdomain_count, "cached": cached_subdomain_count},
        "naabu": {"status": stage_state("naabu", 0), "results": len([r for r in raw_by_stage.get("naabu", []) if r.tool == "naabu"])},
        "httpx": {"status": stage_state("httpx", len(http)), "results": len(http), "total": len(subdomains)},
        "wappalyzer": {"status": stage_state("wappalyzer", len([h for h in http if h.get("tech")])), "results": len([h for h in http if h.get("tech")]), "total": len(http)},
        "js_intel": {"status": stage_state("js_intel", len(js_findings)), "results": len(js_findings), "high": len([j for j in js_findings if j.get("severity") == "high" and j.get("probable_vulnerability")])},
        "ffuf": {"status": "running" if scan.stage == "ffuf" and scan.status in {"running", "stopping"} else "partial" if ffuf_errors and ffuf_success else "failed" if ffuf_errors else "complete" if ffuf_success or dirs else "not_started", "results": len(dirs), "successful_hosts": ffuf_summary.get("successful_hosts", len(ffuf_success)), "failed_hosts": ffuf_summary.get("failed_hosts", len(ffuf_errors)), "total": ffuf_summary.get("total_hosts", len(http))},
        "nuclei": {"status": stage_state("nuclei", len(nuclei_findings)), "results": len(nuclei_findings), "high": len([n for n in nuclei_findings if n.get("severity") == "high"]), "critical": len([n for n in nuclei_findings if n.get("severity") == "critical"])},
        "parameters": {"status": stage_state("parameters", len(parameters)), "results": len(parameters), "suspicious": len([p for p in parameters if p.get("suspicious")]), "katana_input_urls": parameter_summary.get("katana_input_urls"), "lines": parameter_summary.get("lines"), "parse_errors": parameter_summary.get("parse_errors", 0), "raw_compacted": (parameter_summary.get("katana_raw") or {}).get("compacted")},
        "arjun": {"status": stage_state("arjun", len(arjun)), "results": len(arjun), "suspicious": len([p for p in arjun if p.get("suspicious")])},
        "screenshots": {"status": stage_state("screenshots", len(screenshots)), "results": len(screenshots), "input_urls": screenshot_summary.get("input_urls"), "saved": screenshot_summary.get("saved", len(screenshots)), "failed": screenshot_summary.get("failed")},
    }

def _group_observations(rows: list[dict], key_fn) -> list[dict]:
    grouped: dict[tuple | str, dict] = {}
    for row in rows:
        key = key_fn(row)
        variants = list(row.get("variants") or [])
        if not variants:
            variants = [{
                "url": row.get("url") or row.get("source_url"),
                "status_code": row.get("status_code"),
                "source": row.get("source"),
                "sample_value": row.get("sample_value"),
            }]
        count = max(int(row.get("observation_count") or 1), len(variants), 1)
        if key not in grouped:
            item = dict(row)
            item["variants"] = variants
            item["observation_count"] = count
            item["equivalent_ids"] = [row["id"]]
            grouped[key] = item
            continue
        item = grouped[key]
        item["observation_count"] += count
        item["equivalent_ids"].append(row["id"])
        existing_variants = item["variants"]
        for variant in variants:
            if variant not in existing_variants:
                existing_variants.append(variant)
        item["noise_score"] = max(int(item.get("noise_score") or 0), min(100, 5 + item["observation_count"]))
        reasons = list(item.get("noise_reasons") or [])
        duplicate_reason = f"{item['observation_count']} equivalent observations"
        reasons = [reason for reason in reasons if "equivalent observations" not in reason]
        reasons.append(duplicate_reason)
        item["noise_reasons"] = reasons
    return list(grouped.values())


@app.get("/api/targets/{target_id}/results")
def results(target_id: int, scan_id: int | None = None, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(404, "target not found")
    scans_q = db.query(models.Scan).filter_by(target_id=target_id).order_by(models.Scan.id.desc())
    scan = db.get(models.Scan, scan_id) if scan_id else scans_q.first()
    if not scan:
        return {"target": {"id": target.id, "domain": target.domain}, "scans": [], "subdomains": [], "http": [], "dirs": [], "parameters": [], "arjun": [], "js_findings": [], "nuclei_findings": [], "screenshots": [], "raw": []}
    recover_stale_scan(db, scan)
    db.refresh(scan)
    prev = db.query(models.Scan).filter(models.Scan.target_id == target_id, models.Scan.id < scan.id).order_by(models.Scan.id.desc()).first()
    parent_scan = db.get(models.Scan, (scan.config or {}).get("parent_scan_id")) if (scan.config or {}).get("parent_scan_id") else None
    legacy_focused_stage = (scan.config or {}).get("stage") if (scan.config or {}).get("subset_urls") else None
    if not parent_scan and legacy_focused_stage in {"nuclei", "ffuf", "parameters", "js_intel", "screenshots", "wappalyzer"}:
        parent_scan = prev
    focused_stage = ((scan.config or {}).get("focused_stage") or legacy_focused_stage) if parent_scan and parent_scan.target_id == target_id else None
    base_scan_id = parent_scan.id if focused_stage else scan.id
    def data_scan_id(stage: str) -> int:
        return scan.id if focused_stage == stage else base_scan_id
    def rowdict(row, keys):
        d = {k: getattr(row, k) for k in keys}; d["first_seen_scan_id"] = getattr(row, "first_seen_scan_id", None); d["is_new"] = getattr(row, "first_seen_scan_id", scan.id) == scan.id; return d
    subdomain_query = db.query(models.Subdomain).filter_by(target_id=target_id)
    if (scan.config or {}).get("fresh_subdomain_scan", False) or not (scan.config or {}).get("use_cached_subdomains", True):
        subdomain_query = subdomain_query.filter(or_(models.Subdomain.scan_id == scan.id, models.Subdomain.first_seen_scan_id == scan.id))
    subdomains = [rowdict(r, ["id", "name", "sources", "depths", "interesting", "note"]) for r in subdomain_query.all()]
    ports = [rowdict(r, ["id", "host", "ip", "port", "protocol", "source"]) for r in db.query(models.PortResult).filter_by(scan_id=data_scan_id("naabu")).all()]
    raw_http = [rowdict(r, ["id", "url", "asset_key", "variants", "observation_count", "status_code", "title", "tech", "fingerprints", "ports", "response_size", "server", "redirect_chain", "redirect_hops", "final_url", "certificate_fingerprint", "fingerprint_id", "noise_score", "noise_reasons", "novelty_score", "novelty_reasons", "ip", "headers_sent", "response_headers", "interesting", "note"]) for r in db.query(models.HttpxResult).filter_by(scan_id=data_scan_id("httpx")).all()]
    raw_dirs = [rowdict(r, ["id", "base_url", "url", "path", "normalized_path", "method", "status_code", "title", "size", "words", "lines", "content_type", "redirect_location", "duration_ms", "body_hash", "fingerprint_id", "confidence", "filtered_reason", "variants", "observation_count", "noise_score", "noise_reasons", "novelty_score", "novelty_reasons", "open_directory", "headers_sent", "interesting", "note"]) for r in db.query(models.DirbResult).filter_by(scan_id=data_scan_id("ffuf")).all()]
    raw_parameter_rows = [rowdict(r, ["id", "source_url", "base_url", "asset_key", "normalized_path", "param", "sample_value", "method", "source", "suspicious", "reason", "variants", "observation_count", "noise_score", "noise_reasons", "novelty_score", "novelty_reasons", "interesting", "note"]) for r in db.query(models.ParameterResult).filter_by(scan_id=data_scan_id("parameters")).all()]
    http = _group_observations(raw_http, lambda row: row.get("asset_key") or canonical_asset_key(row.get("url")))
    for row in http:
        row["asset_key"] = row.get("asset_key") or canonical_asset_key(row.get("url"))
        hops = row.get("redirect_hops") or []
        if not hops and row.get("redirect_chain"):
            try:
                hops = json.loads(row["redirect_chain"])
            except (TypeError, json.JSONDecodeError):
                hops = [{"url": row["redirect_chain"], "status_code": None}]
        row["redirect"] = {"origin": row.get("url"), "hops": hops, "final": row.get("final_url") or (hops[-1].get("url") if hops else row.get("url"))}
    dirs = _group_observations(raw_dirs, lambda row: (
        canonical_asset_key(row.get("base_url") or row.get("url")),
        row.get("normalized_path") or normalize_path_pattern(row.get("url")),
        str(row.get("method") or "GET").upper(),
    ))
    parameter_rows = _group_observations(raw_parameter_rows, lambda row: (
        row.get("asset_key") or canonical_asset_key(row.get("source_url")),
        row.get("normalized_path") or normalize_path_pattern(row.get("source_url")),
        str(row.get("method") or "GET").upper(),
        row.get("param"),
    ))
    parameters = [r for r in parameter_rows if not str(r.get("source") or "").startswith("arjun-")]
    arjun = [r for r in parameter_rows if str(r.get("source") or "").startswith("arjun-")]
    raw_js_findings = [rowdict(r, ["id", "page_url", "source_url", "file_path", "content_hash", "finding_type", "severity", "indicator", "normalized_indicator", "evidence", "line", "column", "confidence", "classification", "probable_vulnerability", "tags", "variants", "observation_count", "noise_score", "noise_reasons", "novelty_score", "novelty_reasons", "interesting", "note"]) for r in db.query(models.JsFinding).filter_by(scan_id=data_scan_id("js_intel")).all()]
    js_findings = _group_observations(raw_js_findings, lambda row: (
        row.get("content_hash") or hashlib.sha256(str(row.get("source_url") or "").encode()).hexdigest(),
        row.get("finding_type"),
        row.get("normalized_indicator") or normalize_indicator(row.get("indicator")),
    ))
    for finding in js_findings:
        finding["finder"] = _js_finder(finding)
    nuclei_findings = [rowdict(r, ["id", "template_id", "template_name", "severity", "matched_at", "host", "ip", "matcher_name", "type", "description", "extracted_results", "references", "tags", "raw", "interesting", "note"]) for r in db.query(models.NucleiFinding).filter_by(scan_id=data_scan_id("nuclei")).all()]
    screenshots = [{"id": r.id, "url": r.url, "image_path": r.image_path, "image_url": "/screenshots/" + str(Path(r.image_path).relative_to(SCREEN_DIR)).replace('\\', '/'), "tag": r.tag, "interesting": r.interesting, "note": r.note} for r in db.query(models.Screenshot).filter_by(scan_id=data_scan_id("screenshots")).all()]
    raw_scan_ids = [scan.id, base_scan_id] if focused_stage and base_scan_id != scan.id else [scan.id]
    raw_rows = db.query(models.RawOutput).filter(models.RawOutput.scan_id.in_(raw_scan_ids)).all()
    raw = [{"id": r.id, "stage": r.stage, "tool": r.tool, "path": r.path} for r in raw_rows]
    unique_hostnames = {
        (urlparse(row.get("asset_key") or row.get("url") or "").hostname or "").lower()
        for row in http
        if urlparse(row.get("asset_key") or row.get("url") or "").hostname
    }
    endpoint_keys = {
        (canonical_asset_key(row.get("base_url") or row.get("url")), row.get("normalized_path") or normalize_path_pattern(row.get("url")), row.get("method") or "GET")
        for row in dirs
    } | {
        (row.get("asset_key") or canonical_asset_key(row.get("source_url")), row.get("normalized_path") or normalize_path_pattern(row.get("source_url")), row.get("method") or "GET")
        for row in parameter_rows
    }
    summary = {
        "unique_hosts": len(unique_hostnames),
        "unique_endpoints": len(endpoint_keys),
        "unique_parameters": len(parameter_rows),
        "raw_counts": {
            "http": sum(max(int(row.get("observation_count") or 1), 1) for row in raw_http),
            "dirs": sum(max(int(row.get("observation_count") or 1), 1) for row in raw_dirs),
            "parameters": sum(max(int(row.get("observation_count") or 1), 1) for row in raw_parameter_rows),
            "js_findings": sum(max(int(row.get("observation_count") or 1), 1) for row in raw_js_findings),
        },
    }
    return {
        "target": {"id": target.id, "domain": target.domain},
        "scans": [{"id": s.id, "status": s.status, "stage": s.stage, "progress": s.progress, "created_at": s.created_at} for s in scans_q.all()],
        "active_scan": {"id": scan.id, "status": scan.status, "stage": scan.stage, "progress": scan.progress, "error": scan.error},
        "stage_statuses": stage_statuses(db, scan, subdomains, http, dirs, parameters, arjun, js_findings, nuclei_findings, screenshots, raw_rows),
        "summary": summary,
        "subdomains": subdomains,
        "ports": ports,
        "http": http,
        "dirs": dirs,
        "parameters": parameters,
        "arjun": arjun,
        "js_findings": js_findings,
        "nuclei_findings": nuclei_findings,
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

MODEL_MAP = {"subdomains": models.Subdomain, "http": models.HttpxResult, "dirs": models.DirbResult, "parameters": models.ParameterResult, "arjun": models.ParameterResult, "js_findings": models.JsFinding, "nuclei_findings": models.NucleiFinding, "screenshots": models.Screenshot}
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
        for p in data["parameters"]: writer.writerow(["parameter", p["source_url"], p["method"], f"{p['param']} {p.get('reason') or ''}".strip()])
        for p in data["arjun"]: writer.writerow(["arjun", p["source_url"], p["method"], f"{p['param']} {p.get('reason') or ''}".strip()])
        for j in data["js_findings"]: writer.writerow(["js_finding", j["source_url"], j["severity"], f"{j['finding_type']} {j['indicator']}".strip()])
        for n in data["nuclei_findings"]: writer.writerow(["nuclei", n["matched_at"], n["severity"], f"{n['template_id']} {n.get('template_name') or ''}".strip()])
        return Response(buf.getvalue(), media_type="text/csv")
    raise HTTPException(400, "format must be json or csv")
