import hashlib
import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx as pyhttpx
from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.constants import SCAN_BATCH_SIZE, SCAN_FFUF_PARALLEL
from app.recon.pipeline.paths import raw_path, record_raw
from app.recon.runner import run_command
from app.settings_store import load_settings
from app.recon.wordlists import resolve_ffuf_wordlist
from app.recon.wrappers import build_ffuf_command, normalize_content_path, parse_ffuf_json


def response_signature(item: dict) -> tuple:
    return (
        item.get("status_code"),
        item.get("size"),
        item.get("words"),
        item.get("lines"),
        item.get("body_hash"),
    )


def probe_random_paths(
    base_url: str, count: int = 3,
    headers: dict[str, str] | None = None,
    proxy: str | None = None, timeout: int = 10,
) -> list[dict]:
    rows: list[dict] = []
    for _ in range(count):
        path = f"/__ffuf_baseline_{secrets.token_hex(8)}"
        url = base_url.rstrip("/") + path
        try:
            response = pyhttpx.get(
                url, headers=headers or {}, proxy=proxy,
                follow_redirects=False, timeout=timeout,
            )
            body = response.content or b""
            text = body.decode(response.encoding or "utf-8", errors="ignore")
            rows.append({
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "size": len(body),
                "words": len(text.split()),
                "lines": len(text.splitlines()),
                "content_type": response.headers.get("content-type"),
                "redirect_location": response.headers.get("location"),
                "body_hash": hashlib.sha256(body).hexdigest(),
            })
        except Exception as exc:
            rows.append({"url": url, "path": path, "error": str(exc)})
    return rows


def derive_ffuf_filters(baseline: list[dict]) -> dict[str, str]:
    valid = [row for row in baseline if not row.get("error")]
    if len(valid) < 2:
        return {}
    keys = ["status_code", "size", "words", "lines", "body_hash"]
    first_tuple = tuple(valid[0].get(k) for k in keys)
    if not all(tuple(row.get(k) for k in keys) == first_tuple for row in valid[1:]):
        return {}
    filters: dict[str, str] = {}
    if valid[0].get("size") is not None:
        filters["filter_size"] = str(valid[0]["size"])
    if valid[0].get("words") is not None:
        filters["filter_words"] = str(valid[0]["words"])
    if valid[0].get("lines") is not None:
        filters["filter_lines"] = str(valid[0]["lines"])
    return filters


def classify_ffuf_result(result: dict, baseline: list[dict]) -> dict:
    classified = dict(result)
    result_tuple = (
        result.get("status_code"), result.get("size"),
        result.get("words"), result.get("lines"),
    )
    baseline_tuples = {
        (row.get("status_code"), row.get("size"), row.get("words"), row.get("lines"))
        for row in baseline if not row.get("error")
    }
    if result_tuple in baseline_tuples:
        classified["confidence"] = "filtered"
        classified["filtered_reason"] = "matches wildcard baseline response"
    elif result.get("status_code") in {200, 201, 204, 301, 302, 307, 308}:
        classified["confidence"] = "confirmed"
        classified["filtered_reason"] = None
    elif result.get("status_code") in {401, 403}:
        classified["confidence"] = "possible"
        classified["filtered_reason"] = None
    else:
        classified["confidence"] = "unverified"
        classified["filtered_reason"] = None
    return classified


def _ffuf_host(scan: models.Scan, url: str, config: dict, settings, resolved_wordlist) -> dict | None:
    """Run ffuf against a single host. Does NOT use db — runs in thread pool."""
    out = raw_path(scan.id, "ffuf", re.sub(r"[^a-zA-Z0-9_.-]", "_", url), "json")
    cmd = None
    try:
        baseline = probe_random_paths(
            url, int(config.get("ffuf_baseline_count", 3)),
            settings.headers, settings.proxy,
        )
        baseline_out = raw_path(
            scan.id, "ffuf",
            re.sub(r"[^a-zA-Z0-9_.-]", "_", url) + "-baseline", "json",
        )
        baseline_out.write_text(
            json.dumps({"base_url": url, "wildcard_baseline": baseline}, indent=2),
            encoding="utf-8",
        )

        derived_filters = derive_ffuf_filters(baseline)
        filter_size = config.get("ffuf_filter_size") or derived_filters.get("filter_size")
        filter_words = config.get("ffuf_filter_words") or derived_filters.get("filter_words")
        filter_lines = config.get("ffuf_filter_lines") or derived_filters.get("filter_lines")

        cmd = build_ffuf_command(
            url, resolved_wordlist.path, out, config.get("extensions", ""),
            bool(config.get("ffuf_recursive", False)),
            config.get("ffuf_match_codes", "all"),
            filter_size, int(config.get("ffuf_threads", 25)),
            config.get("ffuf_rate"),
            settings.headers, settings.proxy,
            bool(config.get("ffuf_auto_calibration", True)),
            filter_words, filter_lines,
        )
        run_command(cmd, timeout=int(config.get("ffuf_host_timeout", 3600)), scan_id=scan.id)

        baseline_out.write_text(
            json.dumps({"base_url": url, "wildcard_baseline": baseline}, indent=2),
            encoding="utf-8",
        )

        seen_keys: set[tuple] = set()
        items = []
        for item in parse_ffuf_json(out.read_text(errors="ignore")):
            if not item.get("url"):
                continue
            item = classify_ffuf_result(item, baseline)
            item["normalized_path"] = normalize_content_path(item.get("normalized_path") or item.get("path"))
            item["method"] = item.get("method") or "GET"
            dedupe_key = (url, item.get("normalized_path"), item.get("method"))
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            items.append(item)
        return {"url": url, "items": items, "out": out, "baseline_out": baseline_out}

    except Exception as e:
        err = {"url": url, "command": cmd, "error": str(e), "error_type": type(e).__name__}
        out.write_text(json.dumps(err, indent=2), encoding="utf-8")
        return err


def run_ffuf(db: Session, scan: models.Scan, urls: list[str] | None = None) -> dict:
    settings = load_settings()
    config = scan.config or {}
    resolved_wordlist = resolve_ffuf_wordlist(db, config.get("dirb_wordlist_id"))

    metadata = raw_path(scan.id, "ffuf", "wordlist")
    metadata.write_text(
        f"Using {resolved_wordlist.source} FFUF wordlist: {resolved_wordlist.display_name}\n"
        f"Path: {resolved_wordlist.path}\n",
        encoding="utf-8",
    )
    record_raw(db, scan.id, "ffuf", "ffuf-wordlist", metadata)

    urls = urls or [
        r.url for r in db.query(models.HttpxResult).filter(
            models.HttpxResult.scan_id == scan.id,
            models.HttpxResult.status_code < 500,
        ).all()
    ]
    stats = {"total_hosts": len(urls), "successful_hosts": 0, "failed_hosts": 0, "errors": []}
    if not urls:
        return stats

    # Pre-load existing dirb results for fast dedup
    existing_paths: set[tuple[str, str, str]] = set()
    for r in db.query(
        models.DirbResult.base_url, models.DirbResult.normalized_path, models.DirbResult.method,
    ).filter_by(scan_id=scan.id).all():
        existing_paths.add((r.base_url, r.normalized_path, r.method))

    prior_dirb_cache: dict[tuple[str, str], int] = {}
    results: list[dict | None] = []

    # NOTE: _ffuf_host does NOT use the db session — it only runs shell commands.
    # The session is safe to reuse in the main thread after as_completed.
    with ThreadPoolExecutor(max_workers=SCAN_FFUF_PARALLEL) as exc:
        future_map = {
            exc.submit(_ffuf_host, scan, url, config, settings, resolved_wordlist): url
            for url in urls
        }
        for future in as_completed(future_map):
            r = future.result()
            results.append(r)
            if r and "items" in r:
                stats["successful_hosts"] += 1
                record_raw(db, scan.id, "ffuf", "ffuf", r["out"])
                record_raw(db, scan.id, "ffuf", "ffuf-baseline", r["baseline_out"])
            elif r and "error" in r:
                stats["failed_hosts"] += 1
                stats["errors"].append(r)
                record_raw(db, scan.id, "ffuf", "ffuf-error", r["out"])

    # Batch insert all dirb results
    to_add = []
    for r in results:
        if not r or "items" not in r:
            continue
        url = r["url"]
        for item in r["items"]:
            dedupe_key = (url, item.get("normalized_path"), item.get("method"))
            if dedupe_key in existing_paths:
                continue
            existing_paths.add(dedupe_key)
            cache_key = (item.get("normalized_path"), item.get("method"))
            if cache_key not in prior_dirb_cache:
                prior = db.query(models.DirbResult).filter_by(
                    target_id=scan.target_id, normalized_path=cache_key[0], method=cache_key[1],
                ).order_by(models.DirbResult.id.asc()).first()
                prior_dirb_cache[cache_key] = prior.first_seen_scan_id if prior else scan.id
            to_add.append(models.DirbResult(
                target_id=scan.target_id, scan_id=scan.id, base_url=url,
                first_seen_scan_id=prior_dirb_cache[cache_key],
                headers_sent=settings.headers, **item,
            ))
            if len(to_add) >= SCAN_BATCH_SIZE:
                for obj in to_add:
                    db.add(obj)
                db.flush()
                to_add.clear()

    for obj in to_add:
        db.add(obj)
    db.commit()
    return stats
