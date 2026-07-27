import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


def _headers(user_agent: str | None = None, headers: dict[str, str] | None = None) -> list[str]:
    merged = dict(headers or {})
    if user_agent:
        merged.setdefault("User-Agent", user_agent)
    out: list[str] = []
    for key, value in merged.items():
        if key and value is not None:
            out.extend(["-H", f"{key}: {value}"])
    return out


def build_httpx_command(input_file: Path, output_file: Path, user_agent: str | None = None, headers: dict[str, str] | None = None, proxy: str | None = None) -> list[str]:
    cmd = [
        "httpx", "-l", str(input_file), "-json", "-silent", "-status-code", "-title",
        "-tech-detect", "-content-length", "-server", "-ip", "-location",
    ]
    cmd.extend(_headers(user_agent, headers))
    if proxy:
        cmd.extend(["-proxy", proxy])
    cmd.extend(["-o", str(output_file)])
    return cmd


def parse_httpx_jsonl(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        rows.append({
            "url": item.get("url") or item.get("input"),
            "status_code": item.get("status_code"),
            "title": item.get("title"),
            "tech": item.get("tech") or item.get("technologies") or [],
            "response_size": item.get("content_length") or item.get("content-length") or item.get("body_length"),
            "server": item.get("webserver") or item.get("server"),
            "ip": item.get("host") or item.get("ip"),
            "redirect_chain": item.get("location") or item.get("redirect-chain") or item.get("final_url"),
            "response_headers": item.get("header") or item.get("headers") or {},
        })
    return rows


def build_naabu_command(input_file: Path, output_file: Path, ports: str | None = None) -> list[str]:
    ports = ports or "80,81,3000,3001,5000,5173,7001,8000,8008,8080,8081,8443,8888,9000,9443,10443"
    return ["naabu", "-list", str(input_file), "-json", "-silent", "-p", ports, "-o", str(output_file)]


def parse_naabu_jsonl(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            host = item.get("host") or item.get("ip") or item.get("hostname")
            port = item.get("port")
            if host and port:
                rows.append({
                    "host": str(host).strip().lower(),
                    "ip": item.get("ip") if item.get("ip") != host else None,
                    "port": int(port),
                    "protocol": item.get("protocol") or "tcp",
                })
        except json.JSONDecodeError:
            if ":" not in line:
                continue
            host, port = line.rsplit(":", 1)
            if port.isdigit():
                rows.append({"host": host.strip().lower(), "ip": None, "port": int(port), "protocol": "tcp"})
    return rows


def build_wappalyzer_command(input_file: Path, output_file: Path, scan_type: str = "balanced", workers: int = 5) -> list[str]:
    return ["wappalyzer", "-i", str(input_file), "--scan-type", scan_type, "-w", str(workers), "-oJ", str(output_file)]


def parse_wappalyzer_json(text: str) -> dict[str, list[str]]:
    if not text.strip():
        return {}
    data = json.loads(text)
    results: dict[str, list[str]] = {}

    def tech_names(value) -> list[str]:
        if isinstance(value, list):
            names = []
            for item in value:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("technology") or item.get("slug")
                    if name:
                        names.append(str(name))
            return names
        if isinstance(value, dict):
            nested = value.get("technologies") or value.get("tech") or value.get("detected")
            if nested:
                return tech_names(nested)
            metadata_keys = {"url", "target", "input", "host", "status", "status_code", "technologies", "tech", "detected"}
            names = []
            for key, details in value.items():
                if key in metadata_keys:
                    continue
                if isinstance(details, dict) and (
                    "confidence" in details or "categories" in details or "groups" in details or "version" in details
                ):
                    names.append(str(key))
            return names
        return []

    if isinstance(data, dict):
        for url, value in data.items():
            if isinstance(value, dict) and (value.get("url") or value.get("target")):
                results[str(value.get("url") or value.get("target"))] = tech_names(value)
            else:
                results[str(url)] = tech_names(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                url = item.get("url") or item.get("target") or item.get("input")
                if url:
                    results[str(url)] = tech_names(item)
    return {url: sorted(set(names)) for url, names in results.items() if names}


def normalize_content_path(path: str | None) -> str | None:
    if path is None:
        return None
    normalized = re.sub(r"/+", "/", path.strip())
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def build_ffuf_command(
    base_url: str,
    wordlist: Path,
    output_file: Path,
    extensions: str = "",
    recursive: bool = False,
    match_codes: str = "200,204,301,302,307,401,403",
    filter_size: str | None = None,
    threads: int = 25,
    rate: int | None = None,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    auto_calibration: bool = True,
    filter_words: str | None = None,
    filter_lines: str | None = None,
) -> list[str]:
    target = base_url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", target, "-w", str(wordlist), "-of", "json", "-o", str(output_file), "-mc", match_codes, "-t", str(threads)]
    if auto_calibration:
        cmd.append("-ac")
    if extensions:
        cmd.extend(["-e", extensions])
    if recursive:
        cmd.append("-recursion")
    if filter_size:
        cmd.extend(["-fs", str(filter_size)])
    if filter_words:
        cmd.extend(["-fw", str(filter_words)])
    if filter_lines:
        cmd.extend(["-fl", str(filter_lines)])
    if rate:
        cmd.extend(["-rate", str(rate)])
    for key, value in (headers or {}).items():
        cmd.extend(["-H", f"{key}: {value}"])
    if proxy:
        cmd.extend(["-x", proxy])
    return cmd


def parse_ffuf_json(text: str) -> list[dict]:
    if not text.strip():
        return []
    data = json.loads(text)
    rows: list[dict] = []
    for item in data.get("results", []):
        url = item.get("url")
        title = (item.get("title") or "")
        parsed_path = urlparse(url).path if url else None
        size = item.get("length")
        words = item.get("words")
        lines = item.get("lines")
        status = item.get("status")
        duration = item.get("duration")
        duration_ms = int(duration / 1_000_000) if isinstance(duration, int) else duration
        signature = f"{status}:{size}:{words}:{lines}".encode()
        rows.append({
            "url": url,
            "path": parsed_path,
            "normalized_path": normalize_content_path(parsed_path),
            "method": item.get("method") or "GET",
            "status_code": status,
            "size": size,
            "words": words,
            "lines": lines,
            "content_type": item.get("content-type") or item.get("content_type") or item.get("contenttype"),
            "redirect_location": item.get("redirectlocation") or item.get("redirect_location") or item.get("location"),
            "duration_ms": duration_ms,
            "body_hash": item.get("body_hash") or item.get("hash") or hashlib.sha256(signature).hexdigest(),
            "confidence": "unverified",
            "filtered_reason": None,
            "open_directory": "index of" in title.lower() or (parsed_path or "").endswith("/") and item.get("status") == 200 and item.get("words", 0) > 0 and "directory" in title.lower(),
        })
    return rows


def build_gowitness_command(input_file: Path, output_dir: Path, user_agent: str | None = None, proxy: str | None = None) -> list[str]:
    cmd = ["gowitness", "scan", "file", "-f", str(input_file), "--screenshot-path", str(output_dir), "--screenshot-format", "png", "--write-jsonl"]
    if user_agent:
        cmd.extend(["--chrome-user-agent", user_agent])
    if proxy:
        cmd.extend(["--chrome-proxy", proxy])
    return cmd


def build_subfinder_command(domain: str, output_file: Path, recursive: bool = False) -> list[str]:
    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    if recursive:
        cmd.append("-recursive")
    cmd.extend(["-o", str(output_file)])
    return cmd


def build_amass_command(domain: str, output_file: Path) -> list[str]:
    return ["amass", "enum", "-passive", "-d", domain, "-oA", str(output_file.with_suffix(""))]


def build_puredns_command(domain: str, wordlist: Path, resolvers: Path, output_file: Path) -> list[str]:
    return ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-w", str(output_file), "--write-wildcards", str(output_file.with_suffix('.wildcards.txt'))]


def build_gau_command(domain: str) -> list[str]:
    return ["gau", "--subs", domain]


def build_katana_command(
    input_file: Path,
    output_file: Path,
    depth: int = 2,
    headless: bool = False,
    crawl_duration: str = "2m",
) -> list[str]:
    cmd = [
        "katana", "-list", str(input_file), "-silent", "-jsonl", "-jc", "-fx", "-kf", "all",
        "-d", str(depth), "-ct", crawl_duration, "-timeout", "8", "-retry", "0",
        "-p", "3", "-c", "5", "-rl", "30", "-o", str(output_file),
    ]
    if headless:
        cmd.extend(["-headless", "-no-sandbox"])
    return cmd


def build_arjun_command(
    input_file: Path,
    output_file: Path,
    method: str = "GET",
    threads: int = 5,
    request_timeout: int = 10,
    headers: dict[str, str] | None = None,
    stable: bool = True,
) -> list[str]:
    cmd = [
        "arjun", "-i", str(input_file), "-oJ", str(output_file), "-m", method.upper(),
        "-t", str(threads), "-T", str(request_timeout), "-q", "--disable-redirects",
    ]
    if stable:
        cmd.append("--stable")
    if headers:
        header_text = "\n".join(f"{key}: {value}" for key, value in headers.items() if key and value)
        if header_text:
            cmd.extend(["--headers", header_text])
    return cmd


def build_nuclei_command(
    input_file: Path,
    output_file: Path,
    severity: str = "medium,high,critical",
    concurrency: int = 20,
    rate_limit: int = 30,
    timeout: int = 5,
    retries: int = 1,
    unsafe: bool = True,
    templates_path: Path | None = None,
    stats_interval: int = 10,
) -> list[str]:
    cmd = [
        "nuclei",
        "-l", str(input_file),
        "-jsonl",
        "-severity", severity,
        "-c", str(concurrency),
        "-rl", str(rate_limit),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-o", str(output_file),
        "-duc",
        "-stats",
        "-si", str(stats_interval),
    ]
    if templates_path:
        cmd.extend(["-t", str(templates_path)])
    return cmd


def parse_nuclei_jsonl(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        references = info.get("reference") or info.get("references") or []
        if isinstance(references, str):
            references = [references]
        extracted = item.get("extracted-results") or item.get("extracted_results") or []
        if isinstance(extracted, str):
            extracted = [extracted]
        tags = info.get("tags") or item.get("tags") or []
        if isinstance(tags, str):
            tags = [part.strip() for part in tags.split(",") if part.strip()]
        matched_at = item.get("matched-at") or item.get("matched_at") or item.get("url") or item.get("host")
        template_id = item.get("template-id") or item.get("template_id") or item.get("template") or "unknown"
        if not matched_at:
            continue
        rows.append({
            "template_id": str(template_id),
            "template_name": info.get("name"),
            "severity": str(info.get("severity") or item.get("severity") or "info").lower(),
            "matched_at": str(matched_at),
            "host": item.get("host"),
            "ip": item.get("ip"),
            "matcher_name": item.get("matcher-name") or item.get("matcher_name"),
            "type": item.get("type"),
            "description": info.get("description"),
            "extracted_results": [str(value) for value in extracted],
            "references": [str(value) for value in references],
            "tags": [str(value) for value in tags],
            "raw": item,
        })
    return rows


SUSPICIOUS_PARAMETER_PATTERNS = [
    ("redirect", re.compile(r"redirect|redir|return|returnurl|next|continue|callback|url|uri|dest|destination", re.I)),
    ("file/path", re.compile(r"(^|_)(file|path|page|template|folder|dir|download|upload|document|doc|include)($|_)", re.I)),
    ("ssrf", re.compile(r"url|uri|host|domain|endpoint|api|webhook|callback|proxy|feed", re.I)),
    ("auth/session", re.compile(r"token|jwt|key|apikey|api_key|secret|session|sid|auth|password|pass|pwd", re.I)),
    ("object-id", re.compile(r"(^|_)(id|uid|user|account|profile|org|tenant|role|admin)($|_)", re.I)),
    ("command", re.compile(r"cmd|exec|command|process|run|debug|shell", re.I)),
]


def classify_parameter_name(name: str) -> tuple[bool, str | None]:
    reasons = [label for label, pattern in SUSPICIOUS_PARAMETER_PATTERNS if pattern.search(name or "")]
    return bool(reasons), ", ".join(reasons) if reasons else None


def _candidate_urls_from_item(item: dict) -> list[str]:
    candidates = [item.get("url")]
    request = item.get("request")
    if isinstance(request, dict):
        candidates.extend([request.get("endpoint"), request.get("url")])
    return [str(value) for value in candidates if value]


def _request_method_from_item(item: dict) -> str | None:
    request = item.get("request")
    method = request.get("method") if isinstance(request, dict) else item.get("method")
    return str(method).upper() if method else None


def _body_values_from_item(item: dict) -> list[str | dict | list]:
    values: list[str | dict | list] = []
    request = item.get("request")
    containers = [item, request] if isinstance(request, dict) else [item]
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in ("body", "data", "post_data", "payload"):
            value = container.get(key)
            if value:
                values.append(value)
        form = container.get("form") or container.get("forms")
        if form:
            values.append(form)
    return values


def _param_pairs_from_body(value: str | dict | list) -> list[tuple[str, str]]:
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            decoded = json.loads(stripped)
            return _param_pairs_from_body(decoded)
        except json.JSONDecodeError:
            return [(name, sample) for name, sample in parse_qsl(stripped, keep_blank_values=True) if name]
    if isinstance(value, dict):
        pairs: list[tuple[str, str]] = []
        for key, nested in value.items():
            if isinstance(nested, (dict, list)):
                pairs.extend((f"{key}.{child}", sample) for child, sample in _param_pairs_from_body(nested))
            elif key:
                pairs.append((str(key), "" if nested is None else str(nested)))
        return pairs
    if isinstance(value, list):
        pairs: list[tuple[str, str]] = []
        for item in value:
            pairs.extend(_param_pairs_from_body(item))
        return pairs
    return []


def extract_endpoint_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        candidates: list[str] = []
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                candidates = _candidate_urls_from_item(item)
            elif isinstance(item, str):
                candidates = [item]
        except json.JSONDecodeError:
            candidates = [line]
        for candidate in candidates:
            parsed = urlparse(str(candidate))
            if not parsed.scheme or not parsed.netloc:
                continue
            normalized = str(candidate).strip()
            if normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)
    return urls


def extract_parameters_from_urls(text: str, source: str = "url") -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                candidates = _candidate_urls_from_item(item)
                body_values = _body_values_from_item(item)
                request_method = _request_method_from_item(item)
            else:
                candidates = [line]
                body_values = []
                request_method = None
        except json.JSONDecodeError:
            candidates = [line]
            body_values = []
            request_method = None
        for candidate in candidates:
            if not candidate:
                continue
            parsed = urlparse(str(candidate))
            if not parsed.scheme or not parsed.netloc:
                continue
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            pairs = [(name, value, "GET") for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
            if request_method and request_method != "GET":
                pairs.extend((name, value, request_method) for body in body_values for name, value in _param_pairs_from_body(body))
            for name, value, method in pairs:
                if not name:
                    continue
                key = (str(candidate), name, method)
                if key in seen:
                    continue
                seen.add(key)
                suspicious, reason = classify_parameter_name(name)
                rows.append({
                    "source_url": str(candidate),
                    "base_url": base_url,
                    "param": name,
                    "sample_value": value[:512] if value is not None else None,
                    "method": method,
                    "source": source,
                    "suspicious": suspicious,
                    "reason": reason,
                })
    return rows


def parse_arjun_json(text: str, source: str = "arjun") -> list[dict]:
    if not text.strip():
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for url, details in data.items():
        if not isinstance(details, dict):
            continue
        method = str(details.get("method") or "GET").upper()
        params = details.get("params") or []
        if isinstance(params, dict):
            params = list(params.keys())
        if not isinstance(params, list):
            continue
        parsed = urlparse(str(url))
        if not parsed.scheme or not parsed.netloc:
            continue
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        for param in params:
            name = str(param).strip()
            if not name:
                continue
            key = (str(url), name, method)
            if key in seen:
                continue
            seen.add(key)
            suspicious, reason = classify_parameter_name(name)
            rows.append({
                "source_url": str(url),
                "base_url": base_url,
                "param": name,
                "sample_value": None,
                "method": method,
                "source": source,
                "suspicious": suspicious,
                "reason": reason,
            })
    return rows
