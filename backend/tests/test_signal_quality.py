from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app import models
from app.db import SessionLocal, init_db
from app.main import app
from app.recon import pipeline
from app.recon.normalization import (
    canonical_asset_key,
    canonicalize_url,
    is_api_like_endpoint,
    normalize_indicator,
    normalize_path_pattern,
)
from app.recon.wrappers import parse_httpx_jsonl


def make_scan(config=None):
    init_db()
    db = SessionLocal()
    target = models.Target(domain=f"signal-{uuid4().hex}.example")
    db.add(target)
    db.commit()
    db.refresh(target)
    scan = models.Scan(target_id=target.id, status="queued", stage="queued", config=config or {})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return db, target, scan


def test_default_ports_share_canonical_asset_identity():
    assert canonicalize_url("http://Example.com:80") == "http://example.com"
    assert canonicalize_url("https://Example.com:443/login") == "https://example.com/login"
    assert canonical_asset_key("http://example.com:80/path") == canonical_asset_key("http://example.com/path")
    assert canonical_asset_key("https://example.com:443/path") == canonical_asset_key("https://example.com/path")
    assert canonical_asset_key("https://example.com:8443/path") == "https://example.com:8443"


def test_dynamic_path_segments_are_normalized_without_erasing_marketing_slugs():
    assert normalize_path_pattern("/en-us/users/123/550e8400-e29b-41d4-a716-446655440000/1700000000/aabbccddeeff0011") == (
        "/{locale}/users/{id}/{uuid}/{timestamp}/{hash}"
    )
    assert normalize_path_pattern("/solutions/modern-slavery-and-child-labor") == "/solutions/modern-slavery-and-child-labor"


def test_api_detection_ignores_static_and_marketing_links():
    assert is_api_like_endpoint("https://a.example/api/v1/users")
    assert is_api_like_endpoint("https://a.example/graphql")
    assert not is_api_like_endpoint("https://a.example/assets/api-guide.pdf")
    assert not is_api_like_endpoint("https://a.example/partner/en-us/partner.htm")


def test_httpx_redirect_observation_is_canonical_and_groupable():
    rows = parse_httpx_jsonl(
        '{"url":"http://a.example:80","status_code":301,"location":"https://a.example/login"}\n'
        '{"url":"http://a.example","status_code":301,"location":"https://a.example/login"}\n'
    )
    assert {row["asset_key"] for row in rows} == {"http://a.example"}
    assert rows[0]["redirect_hops"] == [{"url": "https://a.example/login", "status_code": None}]
    assert rows[0]["final_url"] == "https://a.example/login"


def test_parameter_storage_deduplicates_dynamic_url_variants():
    db, target, scan = make_scan()
    try:
        stats = pipeline._persist_parameter_texts(db, scan, [
            ("gau", "https://api.example.test/users/123?token=one\n"),
            ("katana", "https://api.example.test/users/456?token=two\n"),
        ])
        rows = db.query(models.ParameterResult).filter_by(scan_id=scan.id).all()
        assert stats["parameters"] == 1
        assert len(rows) == 1
        assert rows[0].asset_key == "https://api.example.test"
        assert rows[0].normalized_path == "/users/{id}"
        assert rows[0].observation_count == 2
        assert len(rows[0].variants) == 2
        assert rows[0].noise_score > 0
    finally:
        db.close()


def test_identical_javascript_content_is_analyzed_once(monkeypatch, tmp_path):
    db, target, scan = make_scan({"js_intel_max_hosts": 5, "js_intel_max_scripts_per_host": 5})
    try:
        db.add(models.HttpxResult(
            target_id=target.id,
            scan_id=scan.id,
            url=f"https://app.{target.domain}",
            asset_key=f"https://app.{target.domain}",
            status_code=200,
            tech=[],
            headers_sent={},
            first_seen_scan_id=scan.id,
        ))
        db.commit()
        monkeypatch.setattr(pipeline, "RAW_DIR", tmp_path / "raw")
        script = 'const endpoint = "/api/v1/users";'

        def fake_fetch(url, settings, timeout, max_bytes):
            if "app.js" not in url:
                return '<script src="/app.js?v=1"></script><script src="/app.js?v=2"></script>', {"status_code": 200, "content_type": "text/html", "bytes": 90}
            return script, {"status_code": 200, "content_type": "application/javascript", "bytes": len(script)}

        monkeypatch.setattr(pipeline, "_fetch_text", fake_fetch)
        monkeypatch.setattr(pipeline, "run_command", lambda *args, **kwargs: ("", ""))
        stats = pipeline.run_js_intel(db, scan)
        findings = db.query(models.JsFinding).filter_by(scan_id=scan.id).all()
        assert stats["bundles"] == 1
        assert stats["duplicate_bundles"] == 1
        assert len(findings) == 1
        assert findings[0].finding_type == "endpoint"
        assert findings[0].content_hash
        assert findings[0].normalized_indicator == normalize_indicator("/api/v1/users")
        assert findings[0].observation_count == 2
        assert findings[0].classification == "interesting_lead"
    finally:
        db.close()


def test_ffuf_body_similarity_filters_near_wildcard_response():
    baseline = [{
        "status_code": 403,
        "size": 1000,
        "words": 75,
        "lines": 20,
        "title": "Access denied",
        "redirect_location": None,
        "body_sample": "request blocked by edge security reference number 123",
    }]
    result = {
        "status_code": 403,
        "size": 1005,
        "words": 76,
        "lines": 20,
        "title": "Different title",
        "redirect_location": None,
        "body_sample": "request blocked by edge security reference number 456",
    }
    classified = pipeline.classify_ffuf_result(result, baseline)
    assert classified["confidence"] == "filtered"
    assert "similar to wildcard baseline" in classified["filtered_reason"]


def test_response_fingerprints_are_reused():
    db, _, _ = make_scan()
    try:
        cache = {}
        item = {"status_code": 200, "size": 12, "words": 2, "lines": 1, "title": "Home", "response_headers": {"content-type": "text/html"}}
        first = pipeline.get_or_create_response_fingerprint(db, item, cache)
        second = pipeline.get_or_create_response_fingerprint(db, dict(item), cache)
        assert first == second
        assert db.query(models.ResponseFingerprint).filter_by(id=first).count() == 1
    finally:
        db.rollback()
        db.close()


def test_results_api_groups_legacy_observations_and_reports_raw_totals():
    db, target, scan = make_scan()
    try:
        db.add_all([
            models.HttpxResult(target_id=target.id, scan_id=scan.id, url="http://a.example:80", status_code=301, tech=[], headers_sent={}, first_seen_scan_id=scan.id),
            models.HttpxResult(target_id=target.id, scan_id=scan.id, url="http://a.example", status_code=301, tech=[], headers_sent={}, first_seen_scan_id=scan.id),
            models.ParameterResult(target_id=target.id, scan_id=scan.id, source_url="https://a.example/users/123?q=one", base_url="https://a.example/users/123", param="q", method="GET", source="gau", first_seen_scan_id=scan.id),
            models.ParameterResult(target_id=target.id, scan_id=scan.id, source_url="https://a.example/users/456?q=two", base_url="https://a.example/users/456", param="q", method="GET", source="katana", first_seen_scan_id=scan.id),
        ])
        scan.status = "complete"
        scan.stage = "complete"
        scan.progress = 100
        db.commit()
        target_id = target.id
    finally:
        db.close()

    data = TestClient(app).get(f"/api/targets/{target_id}/results").json()
    assert len(data["http"]) == 1
    assert data["http"][0]["observation_count"] == 2
    assert len(data["parameters"]) == 1
    assert data["parameters"][0]["observation_count"] == 2
    assert data["summary"]["unique_hosts"] == 1
    assert data["summary"]["unique_parameters"] == 1
    assert data["summary"]["raw_counts"]["http"] == 2
    assert data["summary"]["raw_counts"]["parameters"] == 2
