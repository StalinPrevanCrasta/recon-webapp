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
        })
    return rows


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
    return ["subfinder", "-d", domain, "-silent", "-all", "-o", str(output_file)]


def build_amass_command(domain: str, output_file: Path) -> list[str]:
    return ["amass", "enum", "-passive", "-d", domain, "-o", str(output_file)]


def build_puredns_command(domain: str, wordlist: Path, resolvers: Path, output_file: Path) -> list[str]:
    return ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-w", str(output_file), "--write-wildcards", str(output_file.with_suffix('.wildcards.txt'))]
