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
    monkeypatch.setattr(pipeline, "run_wappalyzer", lambda db, scan, urls=None: {})
    monkeypatch.setattr(pipeline, "run_parameters", lambda db, scan, urls=None: {})

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
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="http://careers-in.floatbot.ai:8080", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()

    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "SCREEN_DIR", tmp_path / "screenshots")

    def fake_run_command(cmd, timeout=None):
        outdir = Path(cmd[cmd.index("--screenshot-path") + 1])
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "https_a.example.png").write_bytes(b"png")
        (outdir / "https_b.example.jpg").write_bytes(b"jpg")
        (outdir / "https_c.example.jpeg").write_bytes(b"jpeg")
        (outdir / "http---careers-in.floatbot.ai-8080.png").write_bytes(b"png")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)

    try:
        pipeline.run_screenshots(db, scan)
        rows = db.query(models.Screenshot).filter_by(scan_id=scan.id).all()
        assert len(rows) == 4
        assert {Path(r.image_path).suffix for r in rows} == {".png", ".jpg", ".jpeg"}
        assert db.query(models.Screenshot).filter_by(scan_id=scan.id, url="http://careers-in.floatbot.ai:8080").count() == 1
    finally:
        db.close()


def test_decode_gowitness_stem_restores_scheme_and_port():
    assert pipeline.decode_gowitness_stem("http---careers-in.floatbot.ai-8080") == "http://careers-in.floatbot.ai:8080"
    assert pipeline.decode_gowitness_stem("https---academy.floatbot.ai-443") == "https://academy.floatbot.ai:443"


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


def test_execute_scan_marks_stopped_when_stop_requested_between_stages(monkeypatch):
    db, _, scan = make_scan({"run_naabu": True, "run_ffuf": False, "run_parameters": False, "run_screenshots": False})
    scan_id = scan.id
    db.close()
    events = []

    def stop_after_subdomains(db, scan):
        events.append("subdomains")
        scan.status = "stopping"
        db.commit()
        return ["a.example"]

    def should_not_run(*args, **kwargs):
        events.append("unexpected")
        return []

    monkeypatch.setattr(pipeline, "enumerate_subdomains", stop_after_subdomains)
    monkeypatch.setattr(pipeline, "run_naabu", should_not_run)
    monkeypatch.setattr(pipeline, "run_httpx", should_not_run)
    monkeypatch.setattr(pipeline, "run_wappalyzer", should_not_run)

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        row = db.get(models.Scan, scan_id)
        assert events == ["subdomains"]
        assert row.status == "stopped"
        assert row.stage == "stopped"
        assert row.error == "Scan stopped by user"
    finally:
        db.close()


def test_enumerate_subdomains_includes_root_domain(monkeypatch, tmp_path):
    db, target, scan = make_scan()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: set())

    def fake_run_command(cmd, timeout=None):
        if cmd[0] == "subfinder":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("api.example.com\n", encoding="utf-8")
            return "", ""
        if cmd[0] == "amass":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("", encoding="utf-8")
            return "", ""
        raise AssertionError(cmd)

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert target.domain in names
        row = db.query(models.Subdomain).filter_by(target_id=target.id, name=target.domain).one()
        assert row.sources == ["root"]
    finally:
        db.close()


def test_enumerate_subdomains_skips_crtsh_by_default(monkeypatch, tmp_path):
    db, target, scan = make_scan()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: (_ for _ in ()).throw(AssertionError("crtsh should not run by default")))

    def fake_run_command(cmd, timeout=None):
        if cmd[0] == "subfinder":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("api.example.com\n", encoding="utf-8")
            return "", ""
        raise AssertionError(cmd)

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert "api.example.com" in names
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id).all()}
        assert "subfinder" in raw_tools
        assert "crtsh" not in raw_tools
    finally:
        db.close()


def test_enumerate_subdomains_uses_crtsh_only_when_enabled(monkeypatch, tmp_path):
    db, target, scan = make_scan({"use_crtsh": True})
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: {f"cert.{domain}"})

    def fake_run_command(cmd, timeout=None):
        if cmd[0] == "subfinder":
            Path(cmd[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(cmd[-1]).write_text("", encoding="utf-8")
            return "", ""
        raise AssertionError(cmd)

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert f"cert.{target.domain}" in names
        row = db.query(models.Subdomain).filter_by(target_id=target.id, name=f"cert.{target.domain}").one()
        assert row.sources == ["crtsh"]
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id).all()}
        assert "crtsh" in raw_tools
    finally:
        db.close()


def test_enumerate_subdomains_can_reuse_cache_without_passive_refresh(monkeypatch, tmp_path):
    db, target, first_scan = make_scan()
    cached_name = f"cached.{target.domain}"
    db.add(models.Subdomain(target_id=target.id, scan_id=first_scan.id, first_seen_scan_id=first_scan.id, name=cached_name, sources=["subfinder"], depths=[0]))
    db.commit()
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config={"use_cached_subdomains": True, "refresh_passive_subdomains": False})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "run_command", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("passive tools should not run")))
    monkeypatch.setattr(pipeline, "crtsh", lambda domain: (_ for _ in ()).throw(AssertionError("crtsh should not run")))

    try:
        names = pipeline.enumerate_subdomains(db, scan)
        assert target.domain in names
        assert cached_name in names
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id).all()}
        assert {"cache", "passive-skipped"}.issubset(raw_tools)
    finally:
        db.close()


def test_fresh_subdomain_scan_limits_downstream_to_current_scan(monkeypatch, tmp_path):
    db, target, old_scan = make_scan()
    old_name = f"old.{target.domain}"
    new_name = f"new.{target.domain}"
    db.add(models.Subdomain(target_id=target.id, scan_id=old_scan.id, first_seen_scan_id=old_scan.id, name=old_name, sources=["subfinder"], depths=[0]))
    db.commit()
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config={"fresh_subdomain_scan": True, "use_cached_subdomains": False})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(models.Subdomain(target_id=target.id, scan_id=scan.id, first_seen_scan_id=scan.id, name=new_name, sources=["subfinder"], depths=[0]))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")

    def fake_run_command(cmd, timeout=None):
        infile = Path(cmd[cmd.index("-l") + 1])
        hosts = set(infile.read_text(encoding="utf-8").splitlines())
        assert new_name in hosts
        assert old_name not in hosts
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("", encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        pipeline.run_httpx(db, scan)
    finally:
        db.close()


def test_run_arjun_uses_selected_urls(monkeypatch, tmp_path):
    db, target, scan = make_scan({
        "run_arjun": True,
        "subset_urls": ["https://api.example.test/search", "https://app.example.test/login"],
        "arjun_methods": "GET",
    })
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    arjun_inputs = []

    def fake_run_command(cmd, timeout=None):
        if cmd[0] != "arjun":
            raise AssertionError(f"only arjun should run, got {cmd}")
        infile = Path(cmd[cmd.index("-i") + 1])
        arjun_inputs.append(infile.read_text(encoding="utf-8").splitlines())
        outfile = Path(cmd[cmd.index("-oJ") + 1])
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text('{"https://api.example.test/search":{"method":"GET","params":["redirect_url","user_id"]}}', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        stats = pipeline.run_arjun(db, scan, scan.config["subset_urls"])
        assert arjun_inputs == [["https://api.example.test/search", "https://app.example.test/login"]]
        assert stats["parameters"] == 2
        rows = db.query(models.ParameterResult).filter_by(scan_id=scan.id).order_by(models.ParameterResult.param).all()
        assert [r.param for r in rows] == ["redirect_url", "user_id"]
        assert all(r.source == "arjun-get" for r in rows)
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="arjun").all()}
        assert "arjun-input" in raw_tools
        assert "gau" not in raw_tools
        assert "katana" not in raw_tools
    finally:
        db.close()


def test_httpx_checks_root_domain_when_no_subdomains_discovered(monkeypatch, tmp_path):
    db, target, scan = make_scan()
    db.add(models.Subdomain(target_id=target.id, scan_id=scan.id, first_seen_scan_id=scan.id, name=target.domain, sources=["root"], depths=[0]))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")

    def fake_run_command(cmd, timeout=None):
        infile = Path(cmd[cmd.index("-l") + 1])
        assert target.domain in infile.read_text(encoding="utf-8").splitlines()
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f'{{"url":"https://{target.domain}","status_code":200}}\n', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        urls = pipeline.run_httpx(db, scan)
        assert urls == [f"https://{target.domain}"]
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
    monkeypatch.setattr(pipeline, "run_wappalyzer", lambda db, scan, urls=None: {})
    monkeypatch.setattr(pipeline, "run_js_intel", lambda db, scan, urls=None: {})
    monkeypatch.setattr(pipeline, "run_parameters", lambda db, scan, urls=None: {})

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
    monkeypatch.setattr(pipeline, "run_wappalyzer", lambda db, scan, urls=None: events.append("wappalyzer") or {})
    monkeypatch.setattr(pipeline, "run_js_intel", lambda db, scan, urls=None: events.append("js_intel") or {})
    monkeypatch.setattr(pipeline, "run_ffuf", lambda db, scan, urls=None: events.append("ffuf") or {"successful_hosts": 0, "failed_hosts": 1, "errors": [{"url": "https://a.example", "error": "timeout"}]})
    monkeypatch.setattr(pipeline, "run_nuclei", lambda db, scan, urls=None: events.append("nuclei") or {})
    monkeypatch.setattr(pipeline, "run_parameters", lambda db, scan, urls=None: events.append("parameters") or {})
    monkeypatch.setattr(pipeline, "run_screenshots", lambda db, scan: events.append("screenshots"))

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        row = db.get(models.Scan, scan_id)
        assert events == ["subdomains", "naabu", "httpx", "wappalyzer", "js_intel", "ffuf", "nuclei", "parameters", "screenshots"]
        assert row.status == "partial"
        assert row.stage == "partial"
        assert "FFUF had 1 host failure" in row.error
    finally:
        db.close()


def test_execute_scan_always_runs_wappalyzer_after_httpx(monkeypatch):
    db, _, scan = make_scan({"run_wappalyzer": False, "run_ffuf": False, "run_screenshots": False})
    scan_id = scan.id
    db.close()
    events = []
    monkeypatch.setattr(pipeline, "enumerate_subdomains", lambda db, scan: events.append("subdomains") or ["a.example"])
    monkeypatch.setattr(pipeline, "run_naabu", lambda db, scan: events.append("naabu") or [])
    monkeypatch.setattr(pipeline, "run_httpx", lambda db, scan: events.append("httpx") or ["https://a.example"])
    monkeypatch.setattr(pipeline, "run_wappalyzer", lambda db, scan, urls=None: events.append("wappalyzer") or {})
    monkeypatch.setattr(pipeline, "run_js_intel", lambda db, scan, urls=None: events.append("js_intel") or {})
    monkeypatch.setattr(pipeline, "run_nuclei", lambda db, scan, urls=None: events.append("nuclei") or {})
    monkeypatch.setattr(pipeline, "run_parameters", lambda db, scan, urls=None: events.append("parameters") or {})

    db = SessionLocal()
    try:
        pipeline.execute_scan(db, scan_id)
        assert events == ["subdomains", "naabu", "httpx", "wappalyzer", "js_intel", "nuclei", "parameters"]
    finally:
        db.close()


def test_analyze_js_text_finds_endpoints_secrets_and_source_sink():
    text = """
      const api = "/api/v1/users";
      const key = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const input = new URLSearchParams(location.search).get("next");
      document.querySelector("#out").innerHTML = input;
    """

    findings = pipeline.analyze_js_text(text, "https://app.example.com/app.js", "https://app.example.com", "example.com")
    pairs = {(row["finding_type"], row["indicator"]) for row in findings}

    assert ("endpoint", "/api/v1/users") in pairs
    assert ("secret", "Google API key") in pairs
    assert any(row["finding_type"] == "source-sink" and row["severity"] == "high" for row in findings)


def test_parse_trufflehog_json_maps_files_to_js_findings():
    output = '{"DetectorName":"Github","Verified":true,"Redacted":"ghp_…abcd","SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/app.js","line":12}}}}\n'
    findings = pipeline.parse_trufflehog_json(output, {"/tmp/app.js": {"page_url": "https://app.example", "source_url": "https://app.example/app.js", "file_path": "/tmp/app.js"}})

    assert findings == [{
        "page_url": "https://app.example",
        "source_url": "https://app.example/app.js",
        "file_path": "/tmp/app.js",
        "finding_type": "trufflehog-secret",
        "severity": "high",
        "indicator": "Github: ghp_…abcd",
        "evidence": "ghp_…abcd",
        "line": 12,
        "column": None,
        "confidence": "verified",
        "tags": ["secret", "trufflehog", "verified"],
    }]


def test_run_js_intel_runs_trufflehog_on_downloaded_bundles(monkeypatch, tmp_path):
    db, target, scan = make_scan({"js_intel_max_hosts": 1, "js_intel_max_scripts_per_host": 2, "js_intel_timeout": 120, "trufflehog_concurrency": 3})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url=f"https://app.{target.domain}", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    calls = []

    def fake_fetch(url, settings, timeout, max_bytes):
        if url.endswith("/app.js"):
            return 'const api="/api/admin";', {"status_code": 200, "content_type": "application/javascript", "bytes": 22}
        return '<script src="/app.js"></script>', {"status_code": 200, "content_type": "text/html", "bytes": 31}

    def fake_command(cmd, timeout=None):
        calls.append(cmd)
        assert cmd[0:2] == ["trufflehog", "filesystem"]
        assert "--json" in cmd
        assert "--results=verified,unknown,unverified" in cmd
        assert "--concurrency=3" in cmd
        return '{"DetectorName":"TestSecret","Verified":true,"Redacted":"tok_…1234","SourceMetadata":{"Data":{"Filesystem":{"file":"' + str(tmp_path / "raw" / f"scan-{scan.id}" / "js_intel" / "x.js").replace("\\", "\\\\") + '","line":1}}}}\n', ""

    monkeypatch.setattr(pipeline, "_fetch_text", fake_fetch)
    monkeypatch.setattr(pipeline, "run_command", fake_command)
    try:
        stats = pipeline.run_js_intel(db, scan)
        assert stats["bundles"] == 1
        assert stats["trufflehog"] == 1
        assert calls
        assert db.query(models.JsFinding).filter_by(scan_id=scan.id, finding_type="trufflehog-secret").count() == 1
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="js_intel").all()}
        assert "trufflehog" in raw_tools
        assert "js-intel-manifest" in raw_tools
    finally:
        db.close()


def test_run_nuclei_scans_live_hosts_and_confirmed_paths_when_enabled(monkeypatch, tmp_path):
    db, target, scan = make_scan({"nuclei_concurrency": 9, "nuclei_rate_limit": 17, "nuclei_timeout": 4, "nuclei_max_urls": 10, "nuclei_severity": "high,critical", "nuclei_include_content_paths": True})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://app.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.add(models.DirbResult(target_id=target.id, scan_id=scan.id, base_url="https://app.example", url="https://app.example/.git/config", normalized_path="/.git/config", method="GET", status_code=200, confidence="confirmed", headers_sent={}, first_seen_scan_id=scan.id))
    db.add(models.DirbResult(target_id=target.id, scan_id=scan.id, base_url="https://app.example", url="https://app.example/noise", normalized_path="/noise", method="GET", status_code=404, confidence="filtered", headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    calls = []

    def fake_run_command(cmd, timeout=None):
        calls.append(cmd)
        infile = Path(cmd[cmd.index("-l") + 1])
        assert infile.read_text(encoding="utf-8").splitlines() == ["https://app.example", "https://app.example/.git/config"]
        assert "--unsafe" not in cmd
        assert "-unsafe" not in cmd
        assert "-duc" in cmd
        assert "-stats" in cmd
        assert ["-si", "10"] == cmd[cmd.index("-si"):cmd.index("-si") + 2]
        assert ["-severity", "high,critical"] == cmd[cmd.index("-severity"):cmd.index("-severity") + 2]
        assert ["-c", "9"] == cmd[cmd.index("-c"):cmd.index("-c") + 2]
        assert ["-rl", "17"] == cmd[cmd.index("-rl"):cmd.index("-rl") + 2]
        assert ["-tags", "exposure,takeover"] == cmd[cmd.index("-tags"):cmd.index("-tags") + 2]
        assert ["-type", "http"] == cmd[cmd.index("-type"):cmd.index("-type") + 2]
        assert "-ni" in cmd
        outfile = Path(cmd[cmd.index("-o") + 1])
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text('{"template-id":"exposed-git-config","info":{"name":"Git Config","severity":"high","tags":"git,exposure"},"matched-at":"https://app.example/.git/config","host":"https://app.example","type":"http"}\n', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        stats = pipeline.run_nuclei(db, scan)
        assert stats["input_urls"] == 2
        assert stats["findings"] == 1
        assert stats["high"] == 1
        row = db.query(models.NucleiFinding).filter_by(scan_id=scan.id).one()
        assert row.template_id == "exposed-git-config"
        assert row.severity == "high"
        assert row.matched_at == "https://app.example/.git/config"
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="nuclei").all()}
        assert {"nuclei-input", "nuclei", "nuclei-log"}.issubset(raw_tools)
        assert calls
    finally:
        db.close()


def test_run_nuclei_light_mode_skips_content_paths_by_default(monkeypatch, tmp_path):
    db, target, scan = make_scan({"nuclei_max_urls": 10})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://app.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.add(models.DirbResult(target_id=target.id, scan_id=scan.id, base_url="https://app.example", url="https://app.example/.git/config", normalized_path="/.git/config", method="GET", status_code=200, confidence="confirmed", headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")

    def fake_run_command(cmd, timeout=None):
        infile = Path(cmd[cmd.index("-l") + 1])
        assert infile.read_text(encoding="utf-8").splitlines() == ["https://app.example"]
        Path(cmd[cmd.index("-o") + 1]).write_text("", encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        stats = pipeline.run_nuclei(db, scan)
        assert stats["input_urls"] == 1
    finally:
        db.close()


def test_run_nuclei_timeout_returns_partial_stats(monkeypatch, tmp_path):
    db, target, scan = make_scan({"nuclei_stage_timeout": 30})
    db.add(models.HttpxResult(target_id=target.id, scan_id=scan.id, url="https://app.example", status_code=200, tech=[], headers_sent={}, first_seen_scan_id=scan.id))
    db.commit()
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")

    def fake_run_command(cmd, timeout=None):
        outfile = Path(cmd[cmd.index("-o") + 1])
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text("", encoding="utf-8")
        raise pipeline.CommandError(cmd, -1, "", "timed out")

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)
    try:
        stats = pipeline.run_nuclei(db, scan)
        assert stats["timed_out"] is True
        assert "stage timeout" in stats["error"]
        raw_tools = {r.tool for r in db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="nuclei").all()}
        assert {"nuclei-input", "nuclei-error", "nuclei"}.issubset(raw_tools)
    finally:
        db.close()
