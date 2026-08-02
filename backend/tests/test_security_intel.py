import json

from app.security_intel import (
    analyze_upload,
    classify_secret_finding,
    compare_authorization_cases,
    compare_endpoint_inventory,
    compare_properties,
    extract_js_intelligence,
    parse_artifact,
)


def test_parse_openapi_and_prioritize_undocumented_operations():
    parsed = parse_artifact(json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test"}],
        "paths": {"/users/{id}": {"get": {"operationId": "getUser", "parameters": [{"name": "id"}]}}},
    }), "auto", "openapi.json")
    assert parsed["artifact_type"] == "openapi"
    assert parsed["endpoints"][0]["operation_id"] == "getUser"
    comparison = compare_endpoint_inventory(parsed["endpoints"], [
        {"method": "GET", "path": "https://api.example.test/users/42", "source": "traffic"},
        {"method": "DELETE", "path": "https://api.example.test/internal/users/42", "source": "traffic"},
    ])
    assert comparison["counts"]["undocumented"] == 1
    assert comparison["undocumented"][0]["priority"] >= 75


def test_js_intelligence_separates_categories_and_requires_dom_flow():
    text = '''
      const API_BASE = "https://api.example.test/v2";
      const socket = "wss://events.example.test/ws";
      const routes = "/api/users/:id";
      const env = "staging";
      const featureFlags = {newBilling: true};
      const value = location.hash; target.innerHTML = value;
      const unused = document.referrer;
      query AccountById($accountId: ID!) { account(id: $accountId) { id ownerId } }
      const client_id = "web-client"; const redirect_uri = "https://app.example.test/callback";
      const code_challenge = makePkce(); const state = random();
    '''
    result = extract_js_intelligence(text, "app.js")
    assert result["api_base_urls"] == ["https://api.example.test/v2"]
    assert result["websocket_urls"] == ["wss://events.example.test/ws"]
    assert result["graphql_operations"][0]["operation_name"] == "AccountById"
    assert result["graphql_operations"][0]["variables"][0]["likely_object_id"] is True
    assert len(result["dom_flows"]) == 1
    assert result["oauth"]["uses_pkce"] is True


def test_authorization_property_upload_and_secret_evidence():
    matrix = compare_authorization_cases([
        {"role": "anonymous", "status": 401, "body": {"error": "login"}},
        {"role": "normal user", "session": "Account A", "status": 200, "body": {"id": "123", "email": "a@example.test"}},
        {"role": "organization administrator", "session": "Account B", "status": 200, "body": {"id": "123", "email": "a@example.test", "billingPlan": "pro"}},
    ])
    assert matrix["matrix"][1]["identifiers"][0]["key"] == "id"
    assert matrix["account_comparison"]["shared_object_identifiers"] == [{"path": "$.id", "value": "123"}]
    props = compare_properties({"name": "old", "role": "user"}, {"name": "new", "role": "admin", "isAdmin": True}, {"name": "new", "role": "admin", "isAdmin": True}, ["role", "isAdmin"])
    assert props["finding"] is True
    assert props["severity"] == "high"
    upload = analyze_upload("avatar.jpg", "image/jpeg", b"<svg><script>alert(1)</script></svg>", {"url": "https://cdn.example.test/abc.svg"})
    assert upload["mime_mismatch"] is True
    assert upload["storage_domain"] == "cdn.example.test"
    urgent = classify_secret_finding({"verified": True, "tags": ["verified"]}, in_scope=True, usable=True)
    assert urgent["urgent"] is True
    assert classify_secret_finding({"verified": False}, in_scope=True, usable=True)["urgent"] is False


def test_mobile_plist_is_normalized():
    parsed = parse_artifact('''<?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict><key>APIBaseURL</key><string>https://mobile.example.test/api</string>
    <key>SocketURL</key><string>wss://mobile.example.test/events</string></dict></plist>''', "mobile-config")
    assert {row["path"] for row in parsed["endpoints"]} == {
        "https://mobile.example.test/api", "wss://mobile.example.test/events"
    }
