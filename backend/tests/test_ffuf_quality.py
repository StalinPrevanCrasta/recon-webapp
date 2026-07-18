from pathlib import Path
from uuid import uuid4

from app import models
from app.db import SessionLocal, init_db
from app.recon import pipeline
from app.recon.wrappers import build_ffuf_command, parse_ffuf_json


def make_scan(config=None):
    init_db()
    db = SessionLocal()
    target = models.Target(domain=f"quality-{uuid4().hex}.example")
    db.add(target)
    db.commit()
    db.refresh(target)
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config=config or {})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return db, target, scan


def test_ffuf_command_enables_auto_calibration_and_dynamic_filters(tmp_path):
    out = tmp_path / "ffuf.json"

    cmd = build_ffuf_command(
        base_url="https://a.example",
        wordlist=tmp_path / "common.txt",
        output_file=out,
        auto_calibration=True,
        filter_size="1234",
        filter_words="42",
        filter_lines="9",
    )

    assert "-ac" in cmd
    assert cmd[cmd.index("-fs") + 1] == "1234"
    assert cmd[cmd.index("-fw") + 1] == "42"
    assert cmd[cmd.index("-fl") + 1] == "9"


def test_baseline_filters_derived_only_when_random_responses_match():
    baseline = [
        {"status_code": 403, "size": 1234, "words": 42, "lines": 9, "body_hash": "same"},
        {"status_code": 403, "size": 1234, "words": 42, "lines": 9, "body_hash": "same"},
        {"status_code": 403, "size": 1234, "words": 42, "lines": 9, "body_hash": "same"},
    ]

    filters = pipeline.derive_ffuf_filters(baseline)

    assert filters == {"filter_size": "1234", "filter_words": "42", "filter_lines": "9"}


def test_ffuf_result_matching_wildcard_baseline_is_filtered():
    baseline = [{"status_code": 403, "size": 1234, "words": 42, "lines": 9, "body_hash": "same"}]
    result = {"status_code": 403, "size": 1234, "words": 42, "lines": 9, "url": "https://a.example/.gitignore"}

    classified = pipeline.classify_ffuf_result(result, baseline)

    assert classified["confidence"] == "filtered"
    assert classified["filtered_reason"] == "matches wildcard baseline response"


def test_parse_ffuf_json_extracts_metadata_and_confidence_defaults():
    data = '{"results":[{"url":"https://a.example/api","status":200,"length":456,"words":10,"lines":5,"content-type":"application/json","redirectlocation":"/login","duration":120000000}]}'

    row = parse_ffuf_json(data)[0]

    assert row["normalized_path"] == "/api"
    assert row["method"] == "GET"
    assert row["content_type"] == "application/json"
    assert row["redirect_location"] == "/login"
    assert row["duration_ms"] == 120
    assert row["confidence"] == "unverified"


def test_run_ffuf_stores_baseline_metadata_and_deduplicates_normalized_paths(monkeypatch, tmp_path):
    default_path = tmp_path / "common.txt"
    default_path.write_text("admin\n", encoding="utf-8")
    monkeypatch.setenv("DEFAULT_FFUF_WORDLIST", str(default_path))
    monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(pipeline, "probe_random_paths", lambda *args, **kwargs: [
        {"status_code": 403, "size": 999, "words": 10, "lines": 3, "body_hash": "wild"},
        {"status_code": 403, "size": 999, "words": 10, "lines": 3, "body_hash": "wild"},
        {"status_code": 403, "size": 999, "words": 10, "lines": 3, "body_hash": "wild"},
    ])
    db, target, scan = make_scan({"run_ffuf": True, "dirb_wordlist_id": None})
    seen = {}

    def fake_run_command(cmd, timeout=None):
        seen["cmd"] = cmd
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text('{"results":[{"url":"https://a.example/admin//","status":403,"length":999,"words":10,"lines":3},{"url":"https://a.example/admin/","status":403,"length":999,"words":10,"lines":3},{"url":"https://a.example/api","status":200,"length":50,"words":5,"lines":1,"content-type":"application/json"}]}', encoding="utf-8")
        return "", ""

    monkeypatch.setattr(pipeline, "run_command", fake_run_command)

    try:
        pipeline.run_ffuf(db, scan, ["https://a.example"])
        rows = db.query(models.DirbResult).filter_by(scan_id=scan.id).all()
        assert len(rows) == 2
        by_path = {r.normalized_path: r for r in rows}
        assert by_path["/admin/"].confidence == "filtered"
        assert by_path["/admin/"].filtered_reason == "matches wildcard baseline response"
        assert by_path["/api"].confidence == "confirmed"
        assert "-ac" in seen["cmd"]
        assert seen["cmd"][seen["cmd"].index("-fs") + 1] == "999"
        raw = db.query(models.RawOutput).filter_by(scan_id=scan.id, stage="ffuf", tool="ffuf-baseline").one()
        assert "wildcard_baseline" in Path(raw.path).read_text(encoding="utf-8")
    finally:
        db.close()
