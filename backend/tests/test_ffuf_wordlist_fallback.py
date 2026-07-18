from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient

from app import models
from app.db import SessionLocal, init_db
from app.main import app
from app.recon import pipeline
from app.recon import wordlists as wordlist_resolver
from app.recon.wordlists import resolve_ffuf_wordlist


def make_wordlist(tmp_path: Path, name: str = "uploaded.txt", content: str = "admin\nlogin\n") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def make_scan(config=None):
    init_db()
    db = SessionLocal()
    domain = f"fallback-{uuid4().hex}.example"
    target = models.Target(domain=domain)
    db.add(target)
    db.commit()
    db.refresh(target)
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config=config or {})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return db, target, scan


def test_user_selected_wordlist_takes_priority_over_default(monkeypatch, tmp_path):
    default_path = make_wordlist(tmp_path, "default-common.txt")
    selected_path = make_wordlist(tmp_path, "custom.txt")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(default_path))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    db, _, _ = make_scan()
    try:
        row = models.Wordlist(kind="dirb", name="custom.txt", path=str(selected_path))
        db.add(row)
        db.commit()
        db.refresh(row)

        resolved = resolve_ffuf_wordlist(db, row.id)

        assert resolved.path == selected_path
        assert resolved.source == "uploaded"
        assert resolved.display_name == "custom.txt"
    finally:
        db.close()


def test_default_wordlist_used_when_no_id_supplied(monkeypatch, tmp_path):
    default_path = make_wordlist(tmp_path, "common.txt")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(default_path))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    db, _, _ = make_scan()
    try:
        resolved = resolve_ffuf_wordlist(db, None)

        assert resolved.path == default_path
        assert resolved.source == "default"
        assert resolved.display_name == "common.txt"
    finally:
        db.close()


def test_bundled_wordlist_used_when_default_missing(monkeypatch, tmp_path):
    bundled_path = make_wordlist(tmp_path, "bundled-common.txt")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(tmp_path / "missing-default.txt"))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", bundled_path)
    db, _, _ = make_scan()
    try:
        resolved = resolve_ffuf_wordlist(db, None)

        assert resolved.path == bundled_path
        assert resolved.source == "bundled"
        assert resolved.display_name == "bundled-common.txt"
    finally:
        db.close()


def test_missing_default_and_bundled_produces_422(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(tmp_path / "missing-default.txt"))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    client = TestClient(app)

    response = client.post("/api/scans/run", json={"domain": f"missing-{uuid4().hex}.example", "run_ffuf": True})

    assert response.status_code == 422
    assert "FFUF is enabled, but no selected or default directory wordlist is available." in response.text


def test_empty_default_is_rejected(monkeypatch, tmp_path):
    empty = make_wordlist(tmp_path, "empty.txt", "")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(empty))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    db, _, _ = make_scan()
    try:
        try:
            resolve_ffuf_wordlist(db, None)
        except ValueError as exc:
            assert "FFUF is enabled, but no selected or default directory wordlist is available." in str(exc)
        else:
            raise AssertionError("empty default should be rejected")
    finally:
        db.close()


def test_ffuf_receives_resolved_default_wordlist_path(monkeypatch, tmp_path):
    default_path = make_wordlist(tmp_path, "common.txt")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(default_path))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    db, target, scan = make_scan({"run_ffuf": True, "dirb_wordlist_id": None})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://a.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    seen = {}

    def fake_run_command(cmd, timeout=None):
        seen["cmd"] = cmd
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text('{"results": []}', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)

    try:
        pipeline.run_ffuf(db, scan, ["https://a.example"])
        assert "-w" in seen["cmd"]
        assert seen["cmd"][seen["cmd"].index("-w") + 1] == str(default_path)
        raw = db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="ffuf", tool="ffuf-wordlist").one()
        assert "Using default FFUF wordlist: common.txt" in Path(raw.path).read_text(encoding="utf-8")
    finally:
        db.close()


def test_ffuf_disabled_scan_does_not_require_any_wordlist(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(tmp_path / "missing-default.txt"))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    monkeypatch.setattr("app.main.run_scan_task", SimpleNamespace(delay=lambda *args, **kwargs: SimpleNamespace(id="test-task")))
    client = TestClient(app)

    response = client.post("/api/scans/run", json={"domain": f"no-ffuf-{uuid4().hex}.example", "run_ffuf": False})

    assert response.status_code == 200
    assert response.json()["task_id"] == "test-task"


def test_health_exposes_default_ffuf_wordlist_status(monkeypatch, tmp_path):
    default_path = make_wordlist(tmp_path, "common.txt")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(default_path))
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", tmp_path / "missing-bundled.txt")
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["ffuf"]["default_wordlist_available"] is True
    assert data["ffuf"]["default_wordlist_name"] == "common.txt"
    assert data["ffuf"]["default_wordlist_source"] == "default"
