from fastapi.testclient import TestClient
from uuid import uuid4
from pathlib import Path

from app import models
from app.db import SessionLocal, init_db
from app.main import app


def test_health_endpoint():
    client = TestClient(app)
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json()['ok'] is True


def test_settings_roundtrip():
    client = TestClient(app)
    payload = {
        "user_agent": "fixed-agent",
        "rotate_user_agents": ["a", "b"],
        "headers": {"X-Test": "1"},
        "proxy": "http://host.docker.internal:8080",
    }
    response = client.put('/api/settings', json=payload)
    assert response.status_code == 200
    assert response.json()["headers"] == {"X-Test": "1"}
    assert client.get('/api/settings').json()["proxy"] == payload["proxy"]


def test_delete_target_removes_target_scans_and_results():
    init_db()
    domain = f"delete-{uuid4().hex}.example"
    db = SessionLocal()
    try:
        target = models.Target(domain=domain)
        db.add(target)
        db.commit()
        db.refresh(target)
        scan = models.Scan(target_id=target.id, status="complete", stage="complete", config={})
        db.add(scan)
        db.commit()
        db.refresh(scan)
        db.add_all([
            models.Subdomain(target_id=target.id, scan_id=scan.id, name=f"api.{domain}", sources=["test"], depths=[0], first_seen_scan_id=scan.id),
            models.PortResult(target_id=target.id, scan_id=scan.id, host=f"api.{domain}", port=443, protocol="tcp", first_seen_scan_id=scan.id),
            models.HttpxResult(target_id=target.id, scan_id=scan.id, url=f"https://api.{domain}", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id),
            models.DirbResult(target_id=target.id, scan_id=scan.id, base_url=f"https://api.{domain}", url=f"https://api.{domain}/admin", status_code=200, headers_sent={}, first_seen_scan_id=scan.id),
            models.ParameterResult(target_id=target.id, scan_id=scan.id, source_url=f"https://api.{domain}/search?q=x", base_url=f"https://api.{domain}/search", param="q", method="GET", source="test", first_seen_scan_id=scan.id),
            models.JsFinding(target_id=target.id, scan_id=scan.id, page_url=f"https://api.{domain}", source_url=f"https://api.{domain}/app.js", finding_type="endpoint", severity="low", indicator="/api/users", confidence="pattern", tags=["endpoint"], first_seen_scan_id=scan.id),
            models.Screenshot(target_id=target.id, scan_id=scan.id, url=f"https://api.{domain}", image_path="/data/screenshots/test.png"),
            models.RawOutput(scan_id=scan.id, stage="httpx", tool="httpx", path="/data/raw/httpx.jsonl"),
        ])
        db.commit()
        target_id = target.id
        scan_id = scan.id
    finally:
        db.close()

    client = TestClient(app)
    response = client.delete(f"/api/targets/{target_id}")

    assert response.status_code == 200
    assert response.json()["deleted"] == {"targets": 1, "scans": 1, "subdomains": 1, "ports": 1, "http": 1, "dirs": 1, "parameters": 1, "js": 1, "screenshots": 1, "raw": 1}
    assert client.get(f"/api/targets/{target_id}/results").status_code == 404
    db = SessionLocal()
    try:
        assert db.get(models.Target, target_id) is None
        assert db.get(models.Scan, scan_id) is None
    finally:
        db.close()



def test_raw_output_endpoint_returns_log_contents(tmp_path):
    init_db()
    db = SessionLocal()
    raw_file = tmp_path / "ffuf-error.json"
    raw_file.write_text('{"error":"timeout","command":["ffuf"]}', encoding="utf-8")
    try:
        target = models.Target(domain=f"raw-{uuid4().hex}.example")
        db.add(target)
        db.commit()
        db.refresh(target)
        scan = models.Scan(target_id=target.id, status="failed", stage="failed", config={})
        db.add(scan)
        db.commit()
        db.refresh(scan)
        raw = models.RawOutput(scan_id=scan.id, stage="ffuf", tool="ffuf-error", path=str(raw_file))
        db.add(raw)
        db.commit()
        db.refresh(raw)
        raw_id = raw.id
    finally:
        db.close()

    response = TestClient(app).get(f"/api/raw/{raw_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["tool"] == "ffuf-error"
    assert body["content"] == '{"error":"timeout","command":["ffuf"]}'


def test_stop_scan_marks_running_scan_as_stopping(monkeypatch):
    init_db()
    db = SessionLocal()
    try:
        target = models.Target(domain=f"stop-{uuid4().hex}.example")
        db.add(target)
        db.commit()
        db.refresh(target)
        scan = models.Scan(target_id=target.id, status="running", stage="ffuf", progress=68, config={})
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    monkeypatch.setattr("app.main.cancel_scan", lambda stopped_scan_id: 2 if stopped_scan_id == scan_id else 0)
    response = TestClient(app).post(f"/api/scans/{scan_id}/stop")

    assert response.status_code == 200
    assert response.json()["killed"] == 2
    db = SessionLocal()
    try:
        stopped = db.get(models.Scan, scan_id)
        assert stopped.status == "stopping"
        assert stopped.stage == "ffuf"
        assert stopped.error == "Scan stop requested by user"
    finally:
        db.close()


def test_manual_arjun_endpoint_queues_existing_scan_and_clears_old_arjun_rows(monkeypatch):
    init_db()
    db = SessionLocal()
    try:
        target = models.Target(domain=f"arjun-{uuid4().hex}.example")
        db.add(target)
        db.commit()
        db.refresh(target)
        scan = models.Scan(target_id=target.id, status="complete", stage="complete", progress=100, config={"run_arjun": False})
        db.add(scan)
        db.commit()
        db.refresh(scan)
        db.add(models.ParameterResult(target_id=target.id, scan_id=scan.id, source_url=f"https://api.{target.domain}/search", base_url=f"https://api.{target.domain}/search", param="debug", method="GET", source="arjun-get", first_seen_scan_id=scan.id))
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    tasks = []
    monkeypatch.setattr("app.main.run_scan_task.delay", lambda queued_scan_id, stage: tasks.append((queued_scan_id, stage)) or type("Task", (), {"id": "task-1"})())
    response = TestClient(app).post(f"/api/scans/{scan_id}/arjun", json={"subset_urls": ["https://api.example/search"], "arjun_methods": "GET"})

    assert response.status_code == 200
    assert tasks == [(scan_id, "arjun")]
    db = SessionLocal()
    try:
        queued = db.get(models.Scan, scan_id)
        assert queued.status == "queued"
        assert queued.stage == "queued:arjun"
        assert queued.config["run_arjun"] is True
        assert queued.config["subset_urls"] == ["https://api.example/search"]
        assert db.query(models.ParameterResult).filter_by(scan_id=scan_id, source="arjun-get").count() == 0
    finally:
        db.close()
