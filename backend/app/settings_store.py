import json
import os
from pathlib import Path
from app.schemas import Settings

DATA_DIR = Path(os.getenv("RECON_DATA_DIR", "/data"))
SETTINGS_PATH = DATA_DIR / "settings.json"

def load_settings() -> Settings:
    if SETTINGS_PATH.exists():
        return Settings.model_validate(json.loads(SETTINGS_PATH.read_text()))
    return Settings()

def save_settings(settings: Settings) -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(settings.model_dump_json(indent=2))
    return settings
