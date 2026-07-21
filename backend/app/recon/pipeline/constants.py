import os
from pathlib import Path

# Performance tuning env vars
SCAN_CONCURRENT_ENUM = int(os.getenv("SCAN_CONCURRENT_ENUM", "2"))
SCAN_FFUF_PARALLEL = int(os.getenv("SCAN_FFUF_PARALLEL", "2"))
SCAN_SCREENSHOT_PARALLEL = int(os.getenv("SCAN_SCREENSHOT_PARALLEL", "1"))
SCAN_BATCH_SIZE = int(os.getenv("SCAN_BATCH_SIZE", "500"))

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
RAW_DIR = DATA_DIR / "raw"
SCREEN_DIR = DATA_DIR / "screenshots"
WORDLIST_DIR = DATA_DIR / "wordlists"
DEFAULT_RESOLVERS = DATA_DIR / "resolvers.txt"
