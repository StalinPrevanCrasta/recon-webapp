from fastapi.testclient import TestClient
from uuid import uuid4

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
            models.HttpxResult(target_id=target.id, scan_id=scan.id, url=f"https://api.{domain}", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id),
            models.DirbResult(target_id=target.id, scan_id=scan.id, base_url=f"https://api.{domain}", url=f"https://api.{domain}/admin", status_code=200, headers_sent={}, first_seen_scan_id=scan.id),
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
    assert response.json()["deleted"] == {"targets": 1, "scans": 1, "subdomains": 1, "http": 1, "dirs": 1, "screenshots": 1, "raw": 1}
    assert client.get(f"/api/targets/{target_id}/results").status_code == 404
    db = SessionLocal()
    try:
        assert db.get(models.Target, target_id) is None
        assert db.get(models.Scan, scan_id) is None
    finally:
        db.close()
