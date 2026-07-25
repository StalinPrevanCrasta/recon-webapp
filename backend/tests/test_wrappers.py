from pathlib import Path

from app.recon.wrappers import build_amass_command, build_httpx_command, build_ffuf_command, build_subfinder_command, parse_httpx_jsonl, parse_ffuf_json


def test_httpx_command_threads_headers_proxy_and_json_input(tmp_path):
    infile = tmp_path / "hosts.txt"
    outfile = tmp_path / "httpx.jsonl"
    cmd = build_httpx_command(
        input_file=infile,
        output_file=outfile,
        user_agent="agent/1.0",
        headers={"X-Forwarded-For": "127.0.0.1", "Cookie": "a=b"},
        proxy="http://host.docker.internal:8080",
    )
    joined = " ".join(cmd)
    assert cmd[:3] == ["httpx", "-l", str(infile)]
    assert "-json" in cmd
    assert "-tech-detect" in cmd
    assert ["-o", str(outfile)] == cmd[-2:]
    assert "User-Agent: agent/1.0" in joined
    assert "X-Forwarded-For: 127.0.0.1" in joined
    assert "Cookie: a=b" in joined
    assert "http://host.docker.internal:8080" in joined


def test_subfinder_command_uses_recursive_sources(tmp_path):
    out = tmp_path / "subfinder.txt"
    cmd = build_subfinder_command("example.com", out)

    assert "-recursive" in cmd
    assert "-all" in cmd
    assert ["-o", str(out)] == cmd[-2:]


def test_parse_httpx_jsonl_extracts_required_fields():
    rows = parse_httpx_jsonl('{"url":"https://a.example","status_code":200,"title":"Home","tech":["nginx"],"content_length":123,"webserver":"nginx","host":"1.2.3.4","location":"/login"}\n')
    assert rows == [{
        "url": "https://a.example",
        "status_code": 200,
        "title": "Home",
        "tech": ["nginx"],
        "response_size": 123,
        "server": "nginx",
        "ip": "1.2.3.4",
        "redirect_chain": "/login",
    }]


def test_ffuf_command_applies_headers_proxy_extensions_filters_and_recursion(tmp_path):
    out = tmp_path / "ffuf.json"
    cmd = build_ffuf_command(
        base_url="https://a.example",
        wordlist=Path('/data/wordlists/dirb/common.txt'),
        output_file=out,
        extensions="php,txt",
        recursive=True,
        match_codes="200,204,301,302,307,401,403",
        filter_size="0",
        threads=20,
        rate=50,
        headers={"X-Auth-Test": "token-value"},
        proxy="http://host.docker.internal:8080",
    )
    joined = " ".join(cmd)
    assert "https://a.example/FUZZ" in cmd
    assert "-recursion" in cmd
    assert "-e" in cmd and "php,txt" in cmd
    assert "-fs" in cmd and "0" in cmd
    assert "-rate" in cmd and "50" in cmd
    assert "X-Auth-Test: token-value" in joined
    assert "http://host.docker.internal:8080" in joined


def test_parse_ffuf_json_flags_index_of_listing():
    data = '{"results":[{"url":"https://a.example/admin/","status":200,"length":456,"words":10,"lines":5,"input":{"FUZZ":"admin"},"title":"Index of /admin"}]}'
    rows = parse_ffuf_json(data)
    assert rows[0]["path"] == "/admin/"
    assert rows[0]["open_directory"] is True


def test_amass_command_uses_supported_output_prefix_flag(tmp_path):
    out = tmp_path / "amass.txt"
    cmd = build_amass_command("example.com", out)

    assert "-o" not in cmd
    assert "-oA" in cmd
    assert cmd[cmd.index("-oA") + 1] == str(out.with_suffix(""))
