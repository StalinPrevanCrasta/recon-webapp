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
    extensions: str = ""
    ffuf_recursive: bool = False
    ffuf_match_codes: str = "all"
    ffuf_filter_size: str | None = None
    ffuf_filter_words: str | None = None
    ffuf_filter_lines: str | None = None
    ffuf_auto_calibration: bool = True
    ffuf_baseline_count: int = Field(default=3, ge=0, le=10)
    ffuf_host_timeout: int = Field(default=300, ge=30, le=3600)
    ffuf_threads: int = Field(default=20, ge=1, le=200)
    ffuf_rate: int | None = Field(default=None, ge=1)
    run_ffuf: bool = True
    run_screenshots: bool = True
    subset_urls: list[str] | None = None

class StageRerunRequest(BaseModel):
    stage: str
    dirb_wordlist_id: int | None = None
    extensions: str = ""
    ffuf_recursive: bool = False
    ffuf_match_codes: str = "all"
    ffuf_filter_size: str | None = None
    ffuf_filter_words: str | None = None
    ffuf_filter_lines: str | None = None
    ffuf_auto_calibration: bool = True
    ffuf_baseline_count: int = 3
    ffuf_host_timeout: int = 300
    ffuf_threads: int = 25
    ffuf_rate: int | None = None
    subset_urls: list[str] | None = None

class InterestingPatch(BaseModel):
    interesting: bool = True
    note: str | None = None
    tag: str | None = None
