import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse


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


def build_subfinder_command(domain: str, output_file: Path) -> list[str]:
    return ["subfinder", "-d", domain, "-silent", "-all", "-recursive", "-o", str(output_file)]


def build_amass_command(domain: str, output_file: Path) -> list[str]:
    return ["amass", "enum", "-passive", "-d", domain, "-oA", str(output_file.with_suffix(""))]


def build_puredns_command(domain: str, wordlist: Path, resolvers: Path, output_file: Path) -> list[str]:
    return ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-w", str(output_file), "--write-wildcards", str(output_file.with_suffix('.wildcards.txt'))]
