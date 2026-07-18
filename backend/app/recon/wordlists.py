import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app import models

DEFAULT_FFUF_WORDLIST_ENV = "DEFAULT_FFUF_WORDLIST"
DEFAULT_FFUF_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
BUNDLED_FFUF_WORDLIST = Path("/app/wordlists/default/common.txt")
FFUF_WORDLIST_UNAVAILABLE = "FFUF is enabled, but no selected or default directory wordlist is available."


@dataclass(frozen=True)
class ResolvedWordlist:
    path: Path
    source: str
    display_name: str


def usable_wordlist(path: Path | str | None) -> bool:
    if not path:
        return False
    candidate = Path(path)
    try:
        return candidate.exists() and candidate.is_file() and os.access(candidate, os.R_OK) and candidate.stat().st_size > 0
    except OSError:
        return False


def ffuf_default_wordlist_path() -> Path:
    return Path(os.getenv(DEFAULT_FFUF_WORDLIST_ENV, DEFAULT_FFUF_WORDLIST))


def resolve_ffuf_wordlist(db: Session, selected_wordlist_id: int | None) -> ResolvedWordlist:
    if selected_wordlist_id:
        row = db.get(models.Wordlist, selected_wordlist_id)
        if row and usable_wordlist(row.path):
            path = Path(row.path)
            return ResolvedWordlist(path=path, source="uploaded", display_name=row.name or path.name)

    default_path = ffuf_default_wordlist_path()
    if usable_wordlist(default_path):
        return ResolvedWordlist(path=default_path, source="default", display_name=default_path.name)

    if usable_wordlist(BUNDLED_FFUF_WORDLIST):
        return ResolvedWordlist(path=BUNDLED_FFUF_WORDLIST, source="bundled", display_name=BUNDLED_FFUF_WORDLIST.name)

    raise ValueError(FFUF_WORDLIST_UNAVAILABLE)


def ffuf_wordlist_status(db: Session | None = None) -> dict:
    try:
        resolved = resolve_ffuf_wordlist(db, None) if db is not None else _resolve_without_db()
        return {
            "default_wordlist_available": True,
            "default_wordlist_name": resolved.display_name,
            "default_wordlist_source": resolved.source,
            "default_wordlist_path": str(resolved.path),
        }
    except ValueError:
        return {
            "default_wordlist_available": False,
            "default_wordlist_name": None,
            "default_wordlist_source": None,
            "default_wordlist_path": str(ffuf_default_wordlist_path()),
        }


def _resolve_without_db() -> ResolvedWordlist:
    default_path = ffuf_default_wordlist_path()
    if usable_wordlist(default_path):
        return ResolvedWordlist(path=default_path, source="default", display_name=default_path.name)
    if usable_wordlist(BUNDLED_FFUF_WORDLIST):
        return ResolvedWordlist(path=BUNDLED_FFUF_WORDLIST, source="bundled", display_name=BUNDLED_FFUF_WORDLIST.name)
    raise ValueError(FFUF_WORDLIST_UNAVAILABLE)
