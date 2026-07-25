from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import models
from app.db import SessionLocal, init_db
from app.main import app
from app.recon import pipeline
from app.recon import wordlists as wordlist_resolver
from app.recon.wrappers import build_gowitness_command


def make_scan(config=None):
    init_db()
    db = SessionLocal()
    domain = f"regression-{uuid4().hex}.example"
    target = models.Target(domain=domain)
    db.add(target)
    db.commit()
    db.refresh(target)
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config=config or {})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return db, target, scan


def test_scan_request_rejects_ffuf_enabled_without_dirb_wordlist(monkeypatch):
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", Path("/missing/bundled/common.txt"))
    client = TestClient(app)

    response = client.post("/api/scans/run", json={"domain": f"reject-{uuid4().hex}.example", "run_ffuf": True, "ffuf_mode": "generic"})

    assert response.status_code == 422
    assert "FFUF is enabled, but no selected or default directory wordlist is available." in response.text


def test_pipeline_rejects_ffuf_enabled_without_dirb_wordlist(monkeypatch):
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", Path("/missing/bundled/common.txt"))
    db, _, scan = make_scan({"run_ffuf": True, "dirb_wordlist_id": None, "ffuf_mode": "generic"})
    try:
        with pytest.raises(ValueError, match="FFUF is enabled, but no selected or default directory wordlist is available"):
            pipeline.run_ffuf(db, scan, ["https://a.example"])
    finally:
        db.close()


def test_execute_scan_records_failure_when_ffuf_validation_fails(monkeypatch):
    monkeypatch.setattr(wordlist_resolver, "BUNDLED_FFUF_WORDLIST", Path("/missing/bundled/common.txt"))
    db, _, scan = make_scan({"run_ffuf": True, "dirb_wordlist_id": None, "run_screenshots": False, "ffuf_mode": "generic"})
    scan_id = scan.id
    db.close()

    monkeypatch.setattr(pipeline, "enumerate_subdomains", lambda db, scan: ["a.example"])
    monkeypatch.setattr(pipeline, "run_naabu", lambda db, scan: [])
    monkeypatch.setattr(pipeline, "run_httpx", lambda db, scan: ["https://a.example"])

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        failed = db.get(models.Scan, scan_id)
        assert failed.status == "failed"
        assert failed.stage == "failed"
        assert "FFUF is enabled, but no selected or default directory wordlist is available." in failed.error
    finally:
        db.close()


def test_gowitness_uses_current_chrome_flags_and_png_format(tmp_path):
    cmd = build_gowitness_command(tmp_path / "urls.txt", tmp_path / "shots", "agent/1.0", "http://proxy:8080")

    assert "--chrome-user-agent" in cmd
    assert "agent/1.0" in cmd
    assert "--chrome-proxy" in cmd
    assert "http://proxy:8080" in cmd
    assert "--screenshot-format" in cmd
    assert "png" in cmd
    assert "--user-agent" not in cmd
    assert "--proxy" not in cmd


def test_screenshot_import_accepts_png_jpg_and_jpeg(monkeypatch, tmp_path):
    db, target, scan = make_scan({"run_screenshots": True})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://a.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()

    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "SCREEN_DIR", tmp_path / "screenshots")

    def fake_run_command(cmd, timeout=None):
        outdir = Path(cmd[cmd.index("--screenshot-path") + 1])
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "https_a.example.png").write_bytes(b"png")
        (outdir / "https_b.example.jpg").write_bytes(b"jpg")
        (outdir / "https_c.example.jpeg").write_bytes(b"jpeg")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)

    try:
        pipeline.run_screenshots(db, scan)
        rows = db.query(models.Screenshot).filter_by(scan_id=scan.id).all()
        assert len(rows) == 3
        assert {Path(r.image_path).suffix for r in rows} == {".png", ".jpg", ".jpeg"}
    finally:
        db.close()


def test_upsert_subdomain_deduplicates_pending_rows_before_commit():
    db, target, scan = make_scan()
    try:
        pipeline.upsert_subdomain(db, target.id, scan.id, "office.example.com", "subfinder", 0)
        pipeline.upsert_subdomain(db, target.id, scan.id, "office.example.com", "crtsh", 0)
        db.commit()

        rows = db.query(models.Subdomain).filter_by(target_id=target.id, name="office.example.com").all()
        assert len(rows) == 1
        assert rows[0].sources == ["crtsh", "subfinder"]
    finally:
        db.close()



def test_enumerate_subdomains_commits_subfinder_results_before_amass(monkeypatch, tmp_path):
    db, target, scan = make_scan()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: set())

    def fake_run_command(cmd, timeout=None):
        if cmd[0] == "subfinder":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("api.example.com\n", encoding="utf-8")
            return "", ""
        if cmd[0] == "amass":
            check_db = SessionLocal()
            try:
                assert check_db.query(models.Subdomain).filter_by(target_id=target.id, name="api.example.com").count() == 1
            finally:
                check_db.close()
            raise RuntimeError("stop amass after visibility check")
        raise AssertionError(cmd)

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert "api.example.com" in names
    finally:
        db.close()


def test_enumerate_subdomains_uses_bundled_bruteforce_wordlist_only_when_enabled(monkeypatch, tmp_path):
    bundled_wordlist = tmp_path / "subdomains-top1million-110000.txt"
    bundled_wordlist.write_text("deep\n", encoding="utf-8")
    db, target, scan = make_scan({"use_subdomains_top1million_110000": True, "recursion_depth": 1})
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "DEFAULT_RESOLVERS", tmp_path / "resolvers.txt")
    monkeypatch.setattr(pipeline, "BUNDLED_SUBDOMAIN_WORDLISTS", (
        ("use_subdomains_top1million_110000", "puredns-top1m-110k", bundled_wordlist),
    ))
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: set())
    commands = []

    def fake_run_command(cmd, timeout=None):
        commands.append(cmd)
        if cmd[0] == "subfinder":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("", encoding="utf-8")
            return "", ""
        if cmd[0] == "puredns":
            out = Path(cmd[cmd.index("-w") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(f"deep.{cmd[3]}\n", encoding="utf-8")
            return "", ""
        raise AssertionError(cmd)

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert f"deep.{target.domain}" in names
        assert any(cmd[0] == "puredns" and cmd[2] == str(bundled_wordlist) for cmd in commands)
        row = db.query(models.Subdomain).filter_by(target_id=target.id, name=f"deep.{target.domain}").one()
        assert row.sources == ["puredns-top1m-110k"]
    finally:
        db.close()


def test_execute_scan_clears_stale_raw_files_for_reused_scan_id(monkeypatch, tmp_path):
    db, _, scan = make_scan({"run_ffuf": False, "run_screenshots": False})
    scan_id = scan.id
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    stale = tmp_path / "raw" / f"scan-{scan_id}" / "ffuf" / "stale.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("old ffuf output", encoding="utf-8")
    db.close()

    monkeypatch.setattr(pipeline, "enumerate_subdomains", lambda db, scan: [])
    monkeypatch.setattr(pipeline, "run_naabu", lambda db, scan: [])
    monkeypatch.setattr(pipeline, "run_httpx", lambda db, scan: [])

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        assert not stale.exists()
        assert (tmp_path / "raw" / f"scan-{scan_id}").exists()
    finally:
        db.close()



def test_ffuf_host_failure_is_recorded_and_next_host_continues(monkeypatch, tmp_path):
    db, target, scan = make_scan({"run_ffuf": True, "ffuf_host_timeout": 30})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://one.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://two.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "probe_random_paths", lambda *a, **k: [])
    (tmp_path / "common.txt").write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(pipeline, "BUNDLED_TECH_WORDLISTS", {"unknown": tmp_path / "common.txt"})
    calls = []

    def fake_run_command(cmd, timeout=None):
        calls.append(cmd)
        out = Path(cmd[cmd.index("-o") + 1])
        if "one.example" in cmd[cmd.index("-u") + 1]:
            raise TimeoutError("host timed out")
        out.write_text('{"results":[{"url":"https://two.example/admin","status":200,"length":10,"words":1,"lines":1}]}', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        stats = pipeline.run_ffuf(db, scan)
        assert stats["failed_hosts"] == 1
        assert stats["successful_hosts"] == 1
        assert db.query(models.DirbResult).filter_by(scan_id=scan.id).count() == 1
        raw_tools = [r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id).all()]
        assert "ffuf-error" in raw_tools
        assert len(calls) == 2
    finally:
        db.close()


def test_execute_scan_finishes_partial_and_still_runs_screenshots_when_ffuf_has_host_failures(monkeypatch):
    db, _, scan = make_scan({"run_ffuf": True, "run_screenshots": True})
    scan_id = scan.id
    db.close()
    events = []
    monkeypatch.setattr(pipeline, "enumerate_subdomains", lambda db, scan: events.append("subdomains") or ["a.example"])
    monkeypatch.setattr(pipeline, "run_naabu", lambda db, scan: events.append("naabu") or [])
    monkeypatch.setattr(pipeline, "run_httpx", lambda db, scan: events.append("httpx") or ["https://a.example"])
    monkeypatch.setattr(pipeline, "run_ffuf", lambda db, scan, urls=None: events.append("ffuf") or {"successful_hosts": 0, "failed_hosts": 1, "errors": [{"url": "https://a.example", "error": "timeout"}]})
    monkeypatch.setattr(pipeline, "run_screenshots", lambda db, scan: events.append("screenshots"))

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        row = db.get(models.Scan, scan_id)
        assert events == ["subdomains", "naabu", "httpx", "ffuf", "screenshots"]
        assert row.status == "partial"
        assert row.stage == "partial"
        assert "FFUF had 1 host failure" in row.error
    finally:
        db.close()
