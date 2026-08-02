from pydantic import BaseModel, Field

class Settings(BaseModel):
    user_agent: str = "recon-webapp/1.0"
    rotate_user_agents: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None

class RunScanRequest(BaseModel):
    domain: str
    subdomain_wordlist_id: int | None = None
    dirb_wordlist_id: int | None = None
    recursion_depth: int = Field(default=2, ge=0, le=5)
    subfinder_timeout: int = Field(default=300, ge=30, le=1800)
    subfinder_recursive: bool = False
    use_crtsh: bool = False
    use_cached_subdomains: bool = True
    refresh_passive_subdomains: bool = True
    fresh_subdomain_scan: bool = False
    run_amass: bool = False
    use_subdomains_top1million_110000: bool = False
    use_bug_bounty_subdomains_trickest: bool = False
    run_naabu: bool = True
    naabu_ports: str = "80,81,3000,3001,5000,5173,7001,8000,8008,8080,8081,8443,8888,9000,9443,10443"
    naabu_timeout: int = Field(default=1800, ge=30, le=7200)
    wappalyzer_scan_type: str = "balanced"
    wappalyzer_workers: int = Field(default=5, ge=1, le=20)
    wappalyzer_timeout: int = Field(default=1800, ge=30, le=7200)
    amass_timeout: int = Field(default=600, ge=30, le=1800)
    extensions: str = ""
    ffuf_recursive: bool = False
    ffuf_match_codes: str = "all"
    ffuf_filter_size: str | None = None
    ffuf_filter_words: str | None = None
    ffuf_filter_lines: str | None = None
    ffuf_mode: str = "tech"
    ffuf_auto_calibration: bool = True
    ffuf_baseline_count: int = Field(default=3, ge=0, le=10)
    ffuf_host_timeout: int = Field(default=300, ge=30, le=3600)
    ffuf_threads: int = Field(default=20, ge=1, le=200)
    ffuf_rate: int | None = Field(default=None, ge=1)
    max_ffuf_hosts: int | None = Field(default=None, ge=1, le=10000)
    run_ffuf: bool = True
    run_parameters: bool = True
    run_js_intel: bool = True
    js_intel_max_hosts: int = Field(default=80, ge=1, le=1000)
    js_intel_max_scripts_per_host: int = Field(default=25, ge=1, le=200)
    js_intel_max_bytes: int = Field(default=2000000, ge=100000, le=10000000)
    js_intel_timeout: int = Field(default=180, ge=30, le=1800)
    trufflehog_results: str = "verified,unknown,unverified"
    trufflehog_concurrency: int = Field(default=4, ge=1, le=32)
    run_nuclei: bool = False
    nuclei_profile: str = "light"
    nuclei_severity: str = "high,critical"
    nuclei_tags: str = "exposure,takeover"
    nuclei_exclude_tags: str = "dos,fuzz,intrusive,brute-force,bruteforce,slow"
    nuclei_types: str = "http"
    nuclei_templates: str = ""
    nuclei_concurrency: int = Field(default=10, ge=1, le=100)
    nuclei_rate_limit: int = Field(default=25, ge=1, le=500)
    nuclei_timeout: int = Field(default=4, ge=1, le=60)
    nuclei_retries: int = Field(default=0, ge=0, le=5)
    nuclei_stage_timeout: int = Field(default=300, ge=30, le=7200)
    nuclei_max_urls: int = Field(default=25, ge=1, le=10000)
    nuclei_no_interactsh: bool = True
    nuclei_include_content_paths: bool = False
    katana_depth: int = Field(default=2, ge=1, le=5)
    run_katana_headless: bool = False
    parameter_timeout: int = Field(default=240, ge=30, le=3600)
    katana_crawl_duration: str = "2m"
    max_katana_urls: int | None = Field(default=80, ge=1, le=10000)
    max_katana_output_mb: int = Field(default=250, ge=10, le=5000)
    run_arjun: bool = False
    arjun_only: bool = False
    arjun_methods: str = "GET"
    arjun_timeout: int = Field(default=240, ge=30, le=3600)
    arjun_threads: int = Field(default=5, ge=1, le=20)
    arjun_request_timeout: int = Field(default=10, ge=3, le=60)
    arjun_stable: bool = True
    run_screenshots: bool = True
    max_screenshot_urls: int | None = Field(default=None, ge=1, le=10000)
    stale_scan_minutes: int = Field(default=30, ge=5, le=1440)
    subset_urls: list[str] | None = None

class StageRerunRequest(BaseModel):
    stage: str
    dirb_wordlist_id: int | None = None
    subfinder_timeout: int = 300
    subfinder_recursive: bool = False
    use_crtsh: bool = False
    use_cached_subdomains: bool = True
    refresh_passive_subdomains: bool = True
    fresh_subdomain_scan: bool = False
    run_amass: bool = False
    amass_timeout: int = 600
    use_subdomains_top1million_110000: bool = False
    use_bug_bounty_subdomains_trickest: bool = False
    run_naabu: bool = True
    naabu_ports: str = "80,81,3000,3001,5000,5173,7001,8000,8008,8080,8081,8443,8888,9000,9443,10443"
    naabu_timeout: int = 1800
    wappalyzer_scan_type: str = "balanced"
    wappalyzer_workers: int = 5
    wappalyzer_timeout: int = 1800
    extensions: str = ""
    ffuf_recursive: bool = False
    ffuf_match_codes: str = "all"
    ffuf_filter_size: str | None = None
    ffuf_filter_words: str | None = None
    ffuf_filter_lines: str | None = None
    ffuf_mode: str = "tech"
    ffuf_auto_calibration: bool = True
    ffuf_baseline_count: int = 3
    ffuf_host_timeout: int = 300
    ffuf_threads: int = 25
    ffuf_rate: int | None = None
    max_ffuf_hosts: int | None = None
    run_parameters: bool = True
    run_js_intel: bool = True
    js_intel_max_hosts: int = 80
    js_intel_max_scripts_per_host: int = 25
    js_intel_max_bytes: int = 2000000
    js_intel_timeout: int = 180
    trufflehog_results: str = "verified,unknown,unverified"
    trufflehog_concurrency: int = 4
    run_nuclei: bool = False
    nuclei_profile: str = "light"
    nuclei_severity: str = "high,critical"
    nuclei_tags: str = "exposure,takeover"
    nuclei_exclude_tags: str = "dos,fuzz,intrusive,brute-force,bruteforce,slow"
    nuclei_types: str = "http"
    nuclei_templates: str = ""
    nuclei_concurrency: int = 10
    nuclei_rate_limit: int = 25
    nuclei_timeout: int = 4
    nuclei_retries: int = 0
    nuclei_stage_timeout: int = 300
    nuclei_max_urls: int = 25
    nuclei_no_interactsh: bool = True
    nuclei_include_content_paths: bool = False
    katana_depth: int = 2
    run_katana_headless: bool = False
    parameter_timeout: int = 240
    katana_crawl_duration: str = "2m"
    max_katana_urls: int | None = 80
    max_katana_output_mb: int = 250
    run_arjun: bool = False
    arjun_only: bool = False
    arjun_methods: str = "GET"
    arjun_timeout: int = 240
    arjun_threads: int = 5
    arjun_request_timeout: int = 10
    arjun_stable: bool = True
    max_screenshot_urls: int | None = None
    stale_scan_minutes: int = 30
    subset_urls: list[str] | None = None

class InterestingPatch(BaseModel):
    interesting: bool = True
    note: str | None = None
    tag: str | None = None


class ArjunRunRequest(BaseModel):
    subset_urls: list[str] | None = None
    arjun_methods: str = "GET"
    arjun_timeout: int = Field(default=240, ge=30, le=3600)
    arjun_threads: int = Field(default=5, ge=1, le=20)
    arjun_request_timeout: int = Field(default=10, ge=3, le=60)
    arjun_stable: bool = True


class PlaygroundRequestSend(BaseModel):
    target_id: int | None = None
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_type: str = "raw"
    timeout: int = Field(default=20, ge=1, le=120)
    follow_redirects: bool = True
    save: bool = True


class PlaygroundToolRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_type: str = "raw"
    timeout: int = Field(default=120, ge=5, le=600)
    arjun_methods: str = "GET"
    arjun_threads: int = Field(default=5, ge=1, le=20)
    arjun_request_timeout: int = Field(default=10, ge=3, le=60)
    arjun_stable: bool = True
    dalfox_options: str = ""


class ArtifactParseRequest(BaseModel):
    content: str = Field(max_length=10_000_000)
    artifact_type: str = "auto"
    source: str = "uploaded"


class EndpointInventoryCompareRequest(BaseModel):
    documented: list[dict] = Field(default_factory=list, max_length=20_000)
    observed: list[dict] = Field(default_factory=list, max_length=20_000)


class AuthorizationMatrixRequest(BaseModel):
    cases: list[dict] = Field(default_factory=list, min_length=1, max_length=20)


class PropertyCompareRequest(BaseModel):
    original: dict = Field(default_factory=dict)
    attempted: dict = Field(default_factory=dict)
    response: dict = Field(default_factory=dict)
    read_only: list[str] = Field(default_factory=list)


class UploadAnalysisRequest(BaseModel):
    filename: str
    declared_mime: str = "application/octet-stream"
    content_base64: str = Field(default="", max_length=14_000_000)
    response: dict = Field(default_factory=dict)
    retrieval_cases: list[dict] = Field(default_factory=list, max_length=20)


class PayloadCampaignRequest(BaseModel):
    method: str = "GET"
    url_template: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: str = ""
    body_type: str = "raw"
    payloads: list[str] = Field(min_length=1, max_length=200)
    delay_ms: int = Field(default=250, ge=0, le=10_000)
    rate_limit_per_second: float = Field(default=2, gt=0, le=50)
    timeout: int = Field(default=15, ge=1, le=45)
    proxies: list[str] = Field(default_factory=list, max_length=20)
    follow_redirects: bool = True
    time_threshold_ms: int = Field(default=3000, ge=500, le=30_000)


class WebSocketSession(BaseModel):
    label: str
    headers: dict[str, str] = Field(default_factory=dict)
    messages: list[str] = Field(default_factory=list, max_length=50)


class WebSocketCompareRequest(BaseModel):
    url: str
    sessions: list[WebSocketSession] = Field(min_length=1, max_length=2)
    timeout: int = Field(default=10, ge=1, le=30)
