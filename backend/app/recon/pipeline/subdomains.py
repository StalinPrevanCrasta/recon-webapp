import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx as pyhttpx
from sqlalchemy.orm import Session

from app import models
from app.recon.pipeline.constants import DEFAULT_RESOLVERS, SCAN_CONCURRENT_ENUM
from app.recon.pipeline.paths import raw_path, record_raw
from app.recon.runner import run_command
from app.recon.wrappers import build_amass_command, build_puredns_command, build_subfinder_command


def clean_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]


def is_subdomain_of(name: str, domain: str) -> bool:
    name = name.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def _valid_hostname(name: str) -> bool:
    """Basic hostname validation — rejects garbage from enumeration tools."""
    if not name or len(name) > 253:
        return False
    if not re.fullmatch(r"[a-z0-9._-]+", name):
        return False
    labels = name.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return True


def batch_upsert_subdomains(db: Session, target_id: int, scan_id: int, names: list[tuple[str, str, int]]) -> None:
    """Batch upsert many subdomains: each tuple is (name, source, depth). Deduplicates in-batch."""
    if not names:
        return
    existing = {r.name: r for r in db.query(models.Subdomain).filter_by(target_id=target_id).all()}
    to_add = []
    seen_in_batch: set[str] = set()
    for name, source, depth in names:
        name = name.strip().lower().rstrip(".")
        if not name or not _valid_hostname(name) or name in seen_in_batch:
            continue
        seen_in_batch.add(name)
        row = existing.get(name)
        if row:
            row.scan_id = scan_id
            row.sources = sorted(set((row.sources or []) + [source]))
            row.depths = sorted(set((row.depths or []) + [depth]))
        else:
            to_add.append(models.Subdomain(
                target_id=target_id, scan_id=scan_id, name=name,
                sources=[source], depths=[depth], first_seen_scan_id=scan_id,
            ))
    for obj in to_add:
        db.add(obj)
    db.flush()


def crtsh(domain: str) -> set[str]:
    try:
        r = pyhttpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        r.raise_for_status()
        out: set[str] = set()
        for item in r.json():
            for name in str(item.get("name_value", "")).splitlines():
                name = name.replace("*.", "").strip().lower()
                if is_subdomain_of(name, domain):
                    out.add(name)
        return out
    except Exception:
        return set()


def mutate_names(names: set[str], domain: str) -> set[str]:
    words = ["dev", "stage", "staging", "test", "uat", "prod", "admin", "api", "internal"]
    out: set[str] = set()
    for name in names:
        if not is_subdomain_of(name, domain):
            continue
        left = name[: -(len(domain) + 1)] if name != domain else ""
        first = left.split(".")[0] if left else ""
        if not first:
            continue
        for w in words:
            out.add(f"{first}-{w}.{domain}")
            out.add(f"{w}-{first}.{domain}")
            out.add(f"{w}.{name}")
    return out


def _run_enum_tool(name: str, builder, domain, out, timeout, scan_id: int):
    """Run a single enumeration tool. Returns (name, success, error_message)."""
    try:
        run_command(builder(domain, out), timeout=timeout, scan_id=scan_id)
        return name, True, None
    except Exception as e:
        out.write_text(str(e))
        return name, False, str(e)


def enumerate_subdomains(db: Session, scan: models.Scan) -> list[str]:
    config = scan.config or {}
    target = scan.target
    domain = target.domain
    wordlist = db.get(models.Wordlist, config.get("subdomain_wordlist_id")) if config.get("subdomain_wordlist_id") else None
    depth_max = int(config.get("recursion_depth", 2))
    tool_timeouts = {
        "subfinder": int(config.get("subfinder_timeout", 300)),
        "amass": int(config.get("amass_timeout", 120)),
    }
    seen: set[str] = set()

    # Run enumeration tools concurrently (crtsh runs outside the pool since it's a fast HTTP call)
    tool_results: list[tuple[str, Path]] = []
    tool_path_map: dict[str, Path] = {}
    with ThreadPoolExecutor(max_workers=SCAN_CONCURRENT_ENUM) as exc:
        futures = {}
        for tool, builder in [("subfinder", build_subfinder_command), ("amass", build_amass_command)]:
            out = raw_path(scan.id, "subdomains", tool)
            tool_results.append((tool, out))
            tool_path_map[tool] = out
            futures[exc.submit(_run_enum_tool, tool, builder, domain, out, tool_timeouts.get(tool, 300), scan.id)] = tool
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                result = future.result()
                tool_out = tool_path_map.get(tool_name, out)
                if result[1]:
                    record_raw(db, scan.id, "subdomains", tool_name, tool_out)
                else:
                    record_raw(db, scan.id, "subdomains", f"{tool_name}-error", tool_out)
            except Exception:
                tool_out = tool_path_map.get(tool_name, out)
                record_raw(db, scan.id, "subdomains", f"{tool_name}-error", tool_out)

    # crtsh runs in the main thread immediately — it's a fast HTTP request, not a slow tool
    ct_result = crtsh(domain)

    # Process subfinder/amass output — read each file once
    batch_names = []
    for tool, out in tool_results:
        seen_in_file: set[str] = set()
        for line in out.read_text(errors="ignore").splitlines():
            clean = line.strip().lower()
            if not clean or clean in seen_in_file:
                continue
            seen_in_file.add(clean)
            seen.add(clean)
            batch_names.append((clean, tool, 0))
    batch_upsert_subdomains(db, target.id, scan.id, batch_names)

    # Process crtsh results
    ctout = raw_path(scan.id, "subdomains", "crtsh")
    ctout.write_text("\n".join(sorted(ct_result)))
    record_raw(db, scan.id, "subdomains", "crtsh", ctout)
    batch_ct = []
    for name in ct_result:
        clean = name.strip().lower()
        if clean:
            seen.add(clean)
            batch_ct.append((clean, "crtsh", 0))
    batch_upsert_subdomains(db, target.id, scan.id, batch_ct)
    db.commit()

    frontier: set[str] = set(seen) or {domain}
    if wordlist:
        if not DEFAULT_RESOLVERS.exists():
            DEFAULT_RESOLVERS.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n")
        for depth in range(1, depth_max + 1):
            next_frontier: set[str] = set()
            for base in sorted(frontier):
                out = raw_path(scan.id, f"subdomains-depth-{depth}", re.sub(r"[^a-zA-Z0-9_.-]", "_", base))
                try:
                    run_command(
                        build_puredns_command(base, Path(wordlist.path), DEFAULT_RESOLVERS, out),
                        timeout=1800, scan_id=scan.id,
                    )
                    record_raw(db, scan.id, f"subdomains-depth-{depth}", "puredns", out)
                    for name in out.read_text(errors="ignore").splitlines():
                        if name and name not in seen:
                            seen.add(name)
                            next_frontier.add(name)
                except Exception as e:
                    out.write_text(str(e))
                    record_raw(db, scan.id, f"subdomains-depth-{depth}", "puredns-error", out)
            if next_frontier:
                batch_next = [(name, "puredns", depth) for name in next_frontier]
                batch_upsert_subdomains(db, target.id, scan.id, batch_next)
            # Mutations
            batch_mut = []
            for name in mutate_names(next_frontier or frontier, domain):
                if name not in seen:
                    seen.add(name)
                    batch_mut.append((name, "mutation", depth))
            if batch_mut:
                batch_upsert_subdomains(db, target.id, scan.id, batch_mut)
            frontier = next_frontier
            db.commit()
    db.commit()
    return sorted(seen)
