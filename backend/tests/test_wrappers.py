from pathlib import Path

from app.recon.wrappers import build_amass_command, build_arjun_command, build_gau_command, build_httpx_command, build_katana_command, build_ffuf_command, build_naabu_command, build_subfinder_command, build_wappalyzer_command, parse_httpx_jsonl, parse_ffuf_json, parse_naabu_jsonl, parse_wappalyzer_json, extract_endpoint_urls, extract_parameters_from_urls, parse_arjun_json


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


def test_subfinder_command_matches_high_coverage_default(tmp_path):
    out = tmp_path / "subfinder.txt"
    cmd = build_subfinder_command("example.com", out)

    assert "-recursive" not in cmd
    assert "-all" in cmd
    assert ["-o", str(out)] == cmd[-2:]


def test_subfinder_command_can_enable_recursive_sources(tmp_path):
    out = tmp_path / "subfinder.txt"
    cmd = build_subfinder_command("example.com", out, recursive=True)

    assert "-recursive" in cmd
    assert "-all" in cmd
    assert ["-o", str(out)] == cmd[-2:]


def test_naabu_command_and_jsonl_parser(tmp_path):
    infile = tmp_path / "hosts.txt"
    outfile = tmp_path / "naabu.jsonl"
    cmd = build_naabu_command(infile, outfile, "80,8080")

    assert cmd[:3] == ["naabu", "-list", str(infile)]
    assert "-json" in cmd
    assert "80,8080" in cmd
    assert parse_naabu_jsonl('{"host":"a.example","ip":"1.2.3.4","port":8080}\n') == [{
        "host": "a.example",
        "ip": "1.2.3.4",
        "port": 8080,
        "protocol": "tcp",
    }]


def test_wappalyzer_balanced_command_and_json_parser(tmp_path):
    infile = tmp_path / "urls.txt"
    outfile = tmp_path / "wappalyzer.json"
    cmd = build_wappalyzer_command(infile, outfile, "balanced", 5)

    assert cmd == ["wappalyzer", "-i", str(infile), "--scan-type", "balanced", "-w", "5", "-oJ", str(outfile)]
    assert parse_wappalyzer_json('{"https://a.example":[{"name":"Strapi"},{"name":"Nginx"}]}') == {
        "https://a.example": ["Nginx", "Strapi"]
    }
    assert parse_wappalyzer_json('{"https://a.example":{"WordPress":{"confidence":100},"PHP":{"categories":["Programming languages"]},"Open Graph":{"groups":["Other"]}}}') == {
        "https://a.example": ["Open Graph", "PHP", "WordPress"]
    }


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
        "response_headers": {},
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


def test_parameter_discovery_commands_and_parser(tmp_path):
    infile = tmp_path / "urls.txt"
    outfile = tmp_path / "katana.txt"

    assert build_gau_command("example.com") == ["gau", "--subs", "example.com"]
    katana_cmd = build_katana_command(infile, outfile, 3, True)
    assert ["-list", str(infile)] == katana_cmd[1:3]
    assert "-jsonl" in katana_cmd
    assert "-fx" in katana_cmd
    assert "-ct" in katana_cmd
    assert "2m" in katana_cmd
    assert "-headless" in katana_cmd
    assert "-no-sandbox" in katana_cmd
    arjun_cmd = build_arjun_command(infile, outfile, "POST", 4, 9, {"User-Agent": "test-agent"}, True)
    assert arjun_cmd[:5] == ["arjun", "-i", str(infile), "-oJ", str(outfile)]
    assert ["-m", "POST"] == arjun_cmd[5:7]
    assert "--stable" in arjun_cmd
    assert "--headers" in arjun_cmd
    assert "User-Agent: test-agent" in arjun_cmd

    rows = extract_parameters_from_urls("https://a.example/search?q=test&redirect=https%3A%2F%2Fevil.example\n", "gau")
    assert rows == [{
        "source_url": "https://a.example/search?q=test&redirect=https%3A%2F%2Fevil.example",
        "base_url": "https://a.example/search",
        "param": "q",
        "sample_value": "test",
        "method": "GET",
        "source": "gau",
        "suspicious": False,
        "reason": None,
    }, {
        "source_url": "https://a.example/search?q=test&redirect=https%3A%2F%2Fevil.example",
        "base_url": "https://a.example/search",
        "param": "redirect",
        "sample_value": "https://evil.example",
        "method": "GET",
        "source": "gau",
        "suspicious": True,
        "reason": "redirect",
    }]

    post_rows = extract_parameters_from_urls(
        '{"url":"https://a.example/login","request":{"method":"POST","body":"username=alice&token=abc"}}\n',
        "katana",
    )
    assert [row["method"] for row in post_rows] == ["POST", "POST"]
    assert [row["param"] for row in post_rows] == ["username", "token"]
    assert post_rows[1]["suspicious"] is True
    assert post_rows[1]["reason"] == "auth/session"

    endpoints = extract_endpoint_urls('{"url":"https://a.example/api"}\nhttps://a.example/search?q=1\n')
    assert endpoints == ["https://a.example/api", "https://a.example/search?q=1"]

    arjun_rows = parse_arjun_json('{"https://a.example/api":{"params":["token","page"],"method":"GET","headers":{}}}', "arjun-get")
    assert [row["param"] for row in arjun_rows] == ["token", "page"]
    assert arjun_rows[0]["source"] == "arjun-get"
    assert arjun_rows[0]["suspicious"] is True
