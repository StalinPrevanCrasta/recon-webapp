"""Security-workbench parsers and evidence-based comparison helpers.

The functions in this module are intentionally transport agnostic so scans, the
manual playground, and tests can share the same classifications.
"""
from __future__ import annotations

import json
import plistlib
import re
from collections import defaultdict
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlparse

import yaml


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
ID_KEY = re.compile(r"(?:^|_)(?:id|uuid|guid|key|number|slug)$|(?:Id|ID)$", re.I)
ID_VALUE = re.compile(r"^(?:\d{1,18}|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,}|[A-Za-z0-9_-]{12,})$", re.I)
GQL_OPERATION = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*(?:\((.*?)\))?\s*\{",
    re.S,
)
GQL_VARIABLE = re.compile(r"\$([A-Za-z_]\w*)\s*:\s*([\[\]!A-Za-z0-9_]+)")
URL_LITERAL = re.compile(r"['\"]((?:https?|wss?)://[^'\"\s]+)['\"]", re.I)
ROUTE_LITERAL = re.compile(r"['\"](/(?:api|rest|v\d+|auth|oauth|admin|internal|graphql)[^'\"\s]*)['\"]", re.I)
SOURCE_NAMES = r"location(?:\.hash|\.search|\.href)?|document\.URL|document\.referrer|window\.name|postMessage|localStorage|sessionStorage"
SINK_NAMES = r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function|setTimeout|setInterval|location(?:\.href)?"
SECRET_TYPES = {"secret", "trufflehog-secret", "credential"}


def _load_structured(content: str):
    try:
        return json.loads(content)
    except Exception:
        try:
            return yaml.safe_load(content)
        except Exception as exc:
            raise ValueError(f"Artifact is not valid JSON or YAML: {exc}") from exc


def _endpoint(method="GET", path="/", *, source="artifact", documented=True, **extra):
    row = {
        "method": str(method or "GET").upper(),
        "path": str(path or "/"),
        "source": source,
        "documented": bool(documented),
    }
    row.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return row


def parse_openapi(data: dict, source: str) -> list[dict]:
    base = ""
    if data.get("servers"):
        base = str(data["servers"][0].get("url", ""))
    elif data.get("host"):
        base = f"{(data.get('schemes') or ['https'])[0]}://{data['host']}{data.get('basePath', '')}"
    rows = []
    for path, definition in (data.get("paths") or {}).items():
        if not isinstance(definition, dict):
            continue
        for method, operation in definition.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = list(definition.get("parameters") or []) + list(operation.get("parameters") or [])
            rows.append(_endpoint(
                method, urljoin(base.rstrip("/") + "/", str(path).lstrip("/")) if base else path,
                source=source, operation_id=operation.get("operationId"),
                parameters=[p.get("name") for p in parameters if isinstance(p, dict) and p.get("name")],
                scopes=sorted({scope for scheme in (operation.get("security") or []) for scope_list in scheme.values() for scope in (scope_list or [])}),
                tags=operation.get("tags") or [],
            ))
    return rows


def parse_postman(data: dict, source: str) -> list[dict]:
    rows = []
    variables = {v.get("key"): v.get("value", "") for v in data.get("variable", []) if isinstance(v, dict)}

    def replace_vars(value):
        return re.sub(r"{{\s*([^}]+)\s*}}", lambda m: str(variables.get(m.group(1).strip(), m.group(0))), str(value or ""))

    def walk(items, folder=""):
        for item in items or []:
            if item.get("item"):
                walk(item["item"], "/".join(filter(None, [folder, item.get("name", "")])))
                continue
            req = item.get("request") or {}
            raw = (req.get("url") or {}).get("raw") if isinstance(req.get("url"), dict) else req.get("url")
            body = req.get("body") or {}
            rows.append(_endpoint(req.get("method", "GET"), replace_vars(raw), source=source,
                                  operation_id=item.get("name"), folder=folder,
                                  parameters=[q.get("key") for q in (req.get("url") or {}).get("query", []) if q.get("key")] if isinstance(req.get("url"), dict) else [],
                                  body_mode=body.get("mode")))
    walk(data.get("item"))
    return rows


def _unwrap_graphql_type(value):
    chain = []
    while isinstance(value, dict):
        if value.get("name"):
            chain.append(value["name"])
        elif value.get("kind"):
            chain.append(value["kind"])
        value = value.get("ofType")
    return "/".join(chain)


def parse_graphql_introspection(data: dict, source: str) -> list[dict]:
    schema = (data.get("data") or data).get("__schema") or {}
    types = {t.get("name"): t for t in schema.get("types", []) if isinstance(t, dict)}
    rows = []
    for op_kind, root_key in (("query", "queryType"), ("mutation", "mutationType"), ("subscription", "subscriptionType")):
        root_name = (schema.get(root_key) or {}).get("name")
        for field in (types.get(root_name) or {}).get("fields", []):
            rows.append(_endpoint("POST", "/graphql", source=source, operation_type=op_kind,
                                  operation_id=field.get("name"), parameters=[a.get("name") for a in field.get("args", [])],
                                  return_type=_unwrap_graphql_type(field.get("type"))))
    return rows


def extract_graphql_operations(text: str, source: str = "javascript") -> list[dict]:
    operations = []
    for match in GQL_OPERATION.finditer(text or ""):
        kind, name, raw_vars = match.groups()
        variables = [{"name": n, "type": t, "likely_object_id": bool(ID_KEY.search(n))} for n, t in GQL_VARIABLE.findall(raw_vars or "")]
        snippet = text[match.start(): match.start() + 1800]
        identifiers = sorted(set(re.findall(r"\b(?:id|[A-Za-z]+Id|uuid|guid|slug)\b", snippet, re.I)))
        operations.append({"operation_type": kind, "operation_name": name, "variables": variables,
                           "object_identifiers": identifiers, "source": source})
    return operations


def trace_dom_flows(text: str) -> list[dict]:
    """Return only source-to-sink traces. Sources without a reachable sink are omitted."""
    flows = []
    assignment = re.compile(rf"\b(?:const|let|var)\s+(\w+)\s*=\s*([^;]*(?:{SOURCE_NAMES})[^;]*);", re.I)
    for match in assignment.finditer(text or ""):
        variable, source_expr = match.groups()
        tail = text[match.end():match.end() + 2500]
        sink = re.search(rf"({SINK_NAMES})[^;\n]*\b{re.escape(variable)}\b|\b{re.escape(variable)}\b[^;\n]*({SINK_NAMES})", tail, re.I)
        if sink:
            flows.append({"source": source_expr.strip(), "variable": variable,
                          "sink": next((g for g in sink.groups() if g), "unknown"),
                          "confidence": "potential", "severity": "medium",
                          "evidence": (match.group(0) + " … " + sink.group(0))[:600]})
    direct = re.compile(rf"({SINK_NAMES})[^;\n]{{0,300}}({SOURCE_NAMES})", re.I)
    for match in direct.finditer(text or ""):
        flows.append({"source": match.group(2), "sink": match.group(1), "confidence": "potential",
                      "severity": "medium", "evidence": match.group(0)[:600]})
    return flows


def extract_js_intelligence(text: str, source: str = "javascript") -> dict:
    urls = [m.group(1) for m in URL_LITERAL.finditer(text or "")]
    routes = [m.group(1) for m in ROUTE_LITERAL.finditer(text or "")]
    api_bases = sorted(set(u.rstrip("/") for u in urls if re.search(r"/(?:api|rest|v\d+)(?:/|$)", urlparse(u).path, re.I)))
    websockets = sorted(set(u for u in urls if u.lower().startswith(("ws://", "wss://"))))
    envs = sorted(set(re.findall(r"\b(?:NODE_ENV|APP_ENV|environment|env)\s*[:=]\s*['\"]([\w.-]+)", text or "", re.I)))
    flags = sorted(set(re.findall(r"\b(?:featureFlags?|flags?)\.([A-Za-z_]\w*)|\b(?:featureFlags?|flags?)\s*[:=]\s*\{\s*([A-Za-z_]\w*)", text or "", re.I)))
    flags = sorted({value for pair in flags for value in pair if value})
    oauth = {
        key: sorted(set(re.findall(pattern, text or "", re.I)))
        for key, pattern in {
            "client_ids": r"client[_-]?id\s*[:=]\s*['\"]([^'\"]+)",
            "redirect_uris": r"redirect[_-]?uri\s*[:=]\s*['\"]([^'\"]+)",
            "issuers": r"issuer\s*[:=]\s*['\"]([^'\"]+)",
            "audiences": r"audience\s*[:=]\s*['\"]([^'\"]+)",
            "scopes": r"scope\s*[:=]\s*['\"]([^'\"]+)",
        }.items()
    }
    oauth["uses_state"] = bool(re.search(r"\bstate\b", text or ""))
    oauth["uses_pkce"] = bool(re.search(r"code_challenge|code_verifier|S256|pkce", text or "", re.I))
    oauth["account_linking"] = bool(re.search(r"link(?:ed|ing)?[_ -]?(?:account|identity)|connect[_ -]?(?:account|identity)", text or "", re.I))
    return {
        "api_base_urls": api_bases,
        "feature_flags": flags,
        "environments": envs,
        "route_templates": sorted(set(routes)),
        "websocket_urls": websockets,
        "graphql_operations": extract_graphql_operations(text, source),
        "oauth": oauth,
        "dom_flows": trace_dom_flows(text),
        "generic_links": sorted(set(u for u in urls if u not in api_bases and u not in websockets)),
    }


def parse_artifact(content: str, artifact_type: str = "auto", source: str = "uploaded") -> dict:
    kind = (artifact_type or "auto").lower().replace("_", "-")
    data = None
    if kind in {"auto", "openapi", "swagger", "postman", "graphql", "mobile-config", "source-map"}:
        if kind in {"auto", "mobile-config"} and "<plist" in content[:500]:
            try:
                data = plistlib.loads(content.encode("utf-8"))
            except Exception as exc:
                raise ValueError(f"Mobile plist could not be parsed: {exc}") from exc
            if kind == "auto":
                kind = "mobile-config"
        else:
            try:
                data = _load_structured(content)
            except ValueError:
                if kind != "auto":
                    raise
    if kind == "auto":
        if isinstance(data, dict) and (data.get("openapi") or data.get("swagger")):
            kind = "openapi"
        elif isinstance(data, dict) and data.get("info", {}).get("schema", "").startswith("https://schema.getpostman"):
            kind = "postman"
        elif isinstance(data, dict) and ((data.get("data") or data).get("__schema")):
            kind = "graphql"
        elif isinstance(data, dict) and data.get("version") and data.get("sources"):
            kind = "source-map"
        else:
            kind = "javascript"
    endpoints = []
    js = {}
    if kind in {"openapi", "swagger"}:
        endpoints = parse_openapi(data or {}, source)
    elif kind == "postman":
        endpoints = parse_postman(data or {}, source)
    elif kind == "graphql":
        endpoints = parse_graphql_introspection(data or {}, source)
    elif kind == "source-map":
        joined = "\n".join(str(x or "") for x in (data or {}).get("sourcesContent", []))
        js = extract_js_intelligence(joined, source)
        endpoints = [_endpoint("POST" if r.startswith("/graphql") else "GET", r, source=source) for r in js.get("route_templates", [])]
    elif kind in {"javascript", "js"}:
        js = extract_js_intelligence(content, source)
        endpoints = [_endpoint("POST" if r.startswith("/graphql") else "GET", r, source=source) for r in js.get("route_templates", [])]
    elif kind == "mobile-config":
        def walk(value, key=""):
            if isinstance(value, dict):
                for k, v in value.items(): walk(v, str(k))
            elif isinstance(value, list):
                for v in value: walk(v, key)
            elif isinstance(value, str) and re.match(r"^(?:https?|wss?)://", value):
                endpoints.append(_endpoint("GET", value, source=source, config_key=key))
        walk(data or {})
    return {"artifact_type": kind, "endpoints": dedupe_endpoints(endpoints), "javascript": js,
            "summary": {"endpoints": len(dedupe_endpoints(endpoints)), "graphql_operations": len(js.get("graphql_operations", [])),
                        "websockets": len(js.get("websocket_urls", [])), "dom_flows": len(js.get("dom_flows", []))}}


def _endpoint_identity(row):
    raw = row.get("path") or row.get("url") or "/"
    path = urlparse(raw).path or raw
    normalized = re.sub(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})(?=/|$)", "/{id}", path, flags=re.I)
    return str(row.get("method") or "GET").upper(), normalized.rstrip("/") or "/"


def dedupe_endpoints(rows):
    merged = {}
    for row in rows:
        key = _endpoint_identity(row)
        if key not in merged:
            merged[key] = dict(row)
        else:
            merged[key]["sources"] = sorted(set((merged[key].get("sources") or [merged[key].get("source")]) + [row.get("source")]))
    return list(merged.values())


def compare_endpoint_inventory(documented: list[dict], observed: list[dict]) -> dict:
    docs = {_endpoint_identity(row): row for row in documented}
    obs = {_endpoint_identity(row): row for row in observed}
    undocumented = []
    for key in sorted(obs.keys() - docs.keys()):
        row = dict(obs[key])
        method, path = key
        sensitivity = sum(1 for token in ("admin", "internal", "debug", "delete", "token", "user", "account", "billing") if token in path.lower())
        method_weight = 2 if method in {"POST", "PUT", "PATCH", "DELETE"} else 0
        row.update({"documented": False, "priority": min(100, 55 + sensitivity * 8 + method_weight * 10),
                    "priority_reasons": ["Observed but absent from supplied documentation", *( ["State-changing method"] if method_weight else [] )]})
        undocumented.append(row)
    return {"undocumented": sorted(undocumented, key=lambda r: r["priority"], reverse=True),
            "documented_and_observed": [obs[k] for k in sorted(obs.keys() & docs.keys())],
            "documented_not_observed": [docs[k] for k in sorted(docs.keys() - obs.keys())],
            "counts": {"documented": len(docs), "observed": len(obs), "undocumented": len(undocumented)}}


def find_object_identifiers(value, path="$", location="body") -> list[dict]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if (ID_KEY.search(str(key)) or (isinstance(child, str) and ID_VALUE.match(child))) and child not in (None, ""):
                found.append({"path": child_path, "key": str(key), "value": str(child)[:200], "location": location,
                              "confidence": "high" if ID_KEY.search(str(key)) else "medium"})
            found.extend(find_object_identifiers(child, child_path, location))
    elif isinstance(value, list):
        for index, child in enumerate(value[:100]):
            found.extend(find_object_identifiers(child, f"{path}[{index}]", location))
    return found


def _flatten(value, prefix="$"):
    result = {}
    if isinstance(value, dict):
        for key, child in value.items(): result.update(_flatten(child, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value[:50]): result.update(_flatten(child, f"{prefix}[]"))
    else:
        result[prefix] = value
    return result


def compare_authorization_cases(cases: list[dict]) -> dict:
    rows = []
    for case in cases:
        body = case.get("body")
        if isinstance(body, str):
            try: body = json.loads(body)
            except Exception: body = {"$raw": body}
        flat = _flatten(body)
        rows.append({**case, "body": body, "fields": sorted(flat), "identifiers": find_object_identifiers(body)})
    baseline = next((r for r in rows if str(r.get("role", "")).lower() in {"anonymous", "account a", "normal user"}), rows[0] if rows else {})
    base_fields = set(baseline.get("fields", []))
    for row in rows:
        fields = set(row["fields"])
        row["extra_fields"] = sorted(fields - base_fields)
        row["omitted_fields"] = sorted(base_fields - fields)
        row["authorization_signal"] = "potential bypass" if row is not baseline and row.get("status") == baseline.get("status") == 200 and row.get("role") != baseline.get("role") else "review"
    account_a = next((r for r in rows if str(r.get("session", "")).lower() == "account a"), None)
    account_b = next((r for r in rows if str(r.get("session", "")).lower() == "account b"), None)
    account_comparison = None
    if account_a and account_b:
        a_fields, b_fields = set(account_a["fields"]), set(account_b["fields"])
        a_ids = {(item["path"], item["value"]) for item in account_a["identifiers"]}
        b_ids = {(item["path"], item["value"]) for item in account_b["identifiers"]}
        account_comparison = {
            "account_a_status": account_a.get("status"), "account_b_status": account_b.get("status"),
            "extra_fields_for_b": sorted(b_fields - a_fields), "omitted_fields_for_b": sorted(a_fields - b_fields),
            "shared_object_identifiers": [{"path": path, "value": value} for path, value in sorted(a_ids & b_ids)],
            "same_response": account_a.get("status") == account_b.get("status") and account_a.get("body") == account_b.get("body"),
            "authorization_signal": "review shared cross-account object access" if a_ids & b_ids and account_a.get("status") == account_b.get("status") == 200 else "responses differ",
        }
    return {"matrix": rows, "baseline_role": baseline.get("role"), "account_comparison": account_comparison,
            "findings": [{"type": "property-level authorization", "role": r.get("role"), "fields": r["extra_fields"], "severity": "medium"}
                         for r in rows if r["extra_fields"]]}


def compare_properties(original: dict, attempted: dict, response: dict, read_only: list[str] | None = None) -> dict:
    read_only = set(read_only or [])
    added = sorted(set(attempted) - set(original))
    changed = sorted(k for k in attempted if k in original and attempted[k] != original[k])
    accepted_extra = sorted(k for k in added if response.get(k) == attempted.get(k))
    accepted_read_only = sorted(k for k in read_only if k in attempted and response.get(k) == attempted.get(k))
    return {"omitted_fields": sorted(set(original) - set(attempted)), "extra_writable_fields": added,
            "changed_fields": changed, "accepted_extra_fields": accepted_extra,
            "accepted_read_only_fields": accepted_read_only,
            "finding": bool(accepted_extra or accepted_read_only),
            "severity": "high" if accepted_read_only else "medium" if accepted_extra else "none"}


def analyze_upload(filename: str, declared_mime: str, content: bytes, response: dict | None = None, retrieval_cases: list[dict] | None = None) -> dict:
    response = response or {}
    extension = PurePosixPath(filename or "").suffix.lower()
    signatures = [(b"\x89PNG", "image/png"), (b"\xff\xd8\xff", "image/jpeg"), (b"GIF8", "image/gif"), (b"%PDF", "application/pdf"), (b"PK\x03\x04", "application/zip")]
    sniffed = next((mime for magic, mime in signatures if content.startswith(magic)), "text/html" if re.search(br"<\s*(?:html|script|svg)", content[:1024], re.I) else "application/octet-stream")
    location = str(response.get("url") or response.get("location") or "")
    generated = PurePosixPath(urlparse(location).path).name if location else ""
    retrieval = compare_authorization_cases(retrieval_cases or []).get("matrix", [])
    return {"filename": filename, "extension": extension, "declared_mime": declared_mime, "sniffed_mime": sniffed,
            "mime_mismatch": bool(declared_mime and sniffed != "application/octet-stream" and declared_mime.split(";")[0] != sniffed),
            "storage_domain": urlparse(location).netloc, "generated_filename": generated,
            "filename_changed": bool(generated and generated != PurePosixPath(filename).name), "retrieval_authorization": retrieval}


def classify_secret_finding(finding: dict, in_scope: bool = False, usable: bool = False) -> dict:
    verified = bool(finding.get("verified") or "verified" in {str(t).lower() for t in finding.get("tags", [])})
    status = "verified" if verified else "unknown" if finding.get("verified") is None else "unverified"
    urgent = verified and in_scope and usable
    return {**finding, "verification_status": status, "in_scope": in_scope, "usable": usable,
            "urgent": urgent, "ranking": "urgent" if urgent else "high" if verified and in_scope else "review"}
