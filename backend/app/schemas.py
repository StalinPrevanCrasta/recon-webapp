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
    run_ffuf: bool = True
    run_parameters: bool = True
    katana_depth: int = Field(default=2, ge=1, le=5)
    run_katana_headless: bool = False
    parameter_timeout: int = Field(default=240, ge=30, le=3600)
    katana_crawl_duration: str = "2m"
    run_arjun: bool = False
    arjun_only: bool = False
    arjun_methods: str = "GET"
    arjun_timeout: int = Field(default=240, ge=30, le=3600)
    arjun_threads: int = Field(default=5, ge=1, le=20)
    arjun_request_timeout: int = Field(default=10, ge=3, le=60)
    arjun_stable: bool = True
    run_screenshots: bool = True
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
    run_parameters: bool = True
    katana_depth: int = 2
    run_katana_headless: bool = False
    parameter_timeout: int = 240
    katana_crawl_duration: str = "2m"
    run_arjun: bool = False
    arjun_only: bool = False
    arjun_methods: str = "GET"
    arjun_timeout: int = 240
    arjun_threads: int = 5
    arjun_request_timeout: int = 10
    arjun_stable: bool = True
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
