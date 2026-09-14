#!/usr/bin/env python3
"""
update.py — deepdarkCTI markdown -> data.json converter.

Converts 6 markdown files from fastfire/deepdarkCTI into a filtered
data.json, refreshed every 12h via GitHub Actions. Keeps only entries
whose status is ONLINE/VALID.

## Pipeline
1. **Freshness check** — unauthenticated GitHub REST API; skip the run
   entirely if none of the 6 files changed in the last 24h.
2. **Download** — `requests.get()` against `raw.githubusercontent.com`
   for each file. 5MB size cap, 15s timeout per request.
3. **Parse** — extract markdown table rows containing a URL; anything
   outside a `|`-delimited row is ignored.
4. **Filter** — keep rows whose status starts with `ONLINE`/`VALID`
   (case-insensitive, e.g. `ONLINE (Backup)` passes). Rows with no
   recognizable status are dropped.
5. **Write** — overwrite `data.json` only if content changed;
   `stats.json` alongside it.
6. **Commit** — workflow runs `git diff --quiet` and only commits if
   `data.json` actually changed.

## Schema
```
{
  "indicator": "https://example.onion",
  "category": "forum",
  "description": "Name, aliases, extra columns, status qualifiers"
}
```
- `category`: `forum`, `markets`, `telegram_threat_actors`,
  `telegram_infostealer`, `twitter_threat_actors`, `ransomware_gang`.
- `description`: catch-all free text — entry name, secondary columns,
  and a bracketed status qualifier when more specific than bare
  `ONLINE`/`VALID` (e.g. `[ONLINE (Backup)]`).
- No `status` or timestamp fields — only online entries are kept.

## Limitations
- Upstream typos/non-standard status strings aren't fixed — just dropped.
- Ransomware-monitoring sites (e.g. `ransomlook.io`) aren't filtered from
  `ransomware_gang` — no reliable way to distinguish them from parsing alone.
- `ransomware_gang.md` rows are the messiest (creds, PGP keys, mirrors in
  one cell); only the first URL becomes `indicator`, the rest goes into
  `description`.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

REPO = "fastfire/deepdarkCTI"
BRANCH = "main"
OUTPUT_PATH = Path("data.json")
STATS_PATH = Path("stats.json")

# How far back to look for upstream commits before deciding to do any work.
# Set above the 12h cron cadence to absorb GitHub Actions scheduling drift; 
# redundant re-processing is harmless thanks to the idempotency gate.
LOOKBACK_HOURS = 13

# Hard safety cap per downloaded file (defensive; real files are <100KB).
MAX_FILE_BYTES = 5 * 1024 * 1024

REQUEST_TIMEOUT = 15  # seconds
USER_AGENT = "deepdarkcti-feed-bot/1.0 (+https://github.com/%s)" % REPO

TARGET_FILES: dict[str, str] = {
    "forum": "forum.md",
    "markets": "markets.md",
    "telegram_threat_actors": "telegram_threat_actors.md",
    "telegram_infostealer": "telegram_infostealer.md",
    "twitter_threat_actors": "twitter_threat_actors.md",
    "ransomware_gang": "ransomware_gang.md",
}

RAW_URL_TMPL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/{{path}}"
COMMITS_API_TMPL = f"https://api.github.com/repos/{REPO}/commits"

# --------------------------------------------------------------------------
# Regex helpers for pulling links/status out of markdown table cells
# --------------------------------------------------------------------------

# [text](url)  -- tolerate a stray space before '(' (seen in the wild)
MD_LINK_RE = re.compile(r"\[([^\]]*)\]\s*\(\s*([^)\s][^)]*)\)")
# <https://...>
ANGLE_URL_RE = re.compile(r"<\s*(https?://[^>\s]+)\s*>")
# bare https://... not already wrapped in <> or ()
BARE_URL_RE = re.compile(r"(https?://[^\s()<>\[\]|]+)")

STATUS_TOKENS = (
    "ONLINE",
    "OFFLINE",
    "EXPIRED",
    "VALID",
    "SEIZED",
    "PRIVATE",
    "PENDING",
    "DOWN",
    "UNKNOWN",
)
STATUS_TOKEN_RE = re.compile(
    r"\b(" + "|".join(STATUS_TOKENS) + r")\b", re.IGNORECASE
)
SEPARATOR_CELL_RE = re.compile(r"^:?-{1,}:?$")


@dataclass
class Stats:
    """Per-file audit counters, logged to stderr for traceability."""

    table_rows_seen: int = 0
    no_url_skipped: int = 0
    no_status_skipped: int = 0
    offline_skipped: int = 0
    kept: int = 0


# --------------------------------------------------------------------------
# Generic markdown-table parsing primitives
# --------------------------------------------------------------------------


def iter_table_rows(md_text: str):
    """Yield raw cell lists for every pipe-table line in the document.

    Deliberately ignores every line that doesn't start with '|', which
    satisfies "ignore data outside of tables, even if it contains URLs".
    """
    for raw_line in md_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        yield cells


def is_separator_row(cells: list[str]) -> bool:
    non_empty = [c for c in cells if c.strip()]
    if not non_empty:
        return True
    return all(SEPARATOR_CELL_RE.match(c.strip()) for c in non_empty)


def extract_link(cell: str) -> tuple[str, str] | None:
    """Return (link_text, url) for the first link found in a single cell."""
    if not cell:
        return None
    m = MD_LINK_RE.search(cell)
    if m:
        text, url = m.group(1).strip(), m.group(2).strip()
        if url.startswith("http"):
            return text, url
    m = ANGLE_URL_RE.search(cell)
    if m:
        return "", m.group(1).strip()
    m = BARE_URL_RE.search(cell)
    if m:
        return "", m.group(1).strip()
    return None


def extract_link_anywhere(cells: list[str]) -> tuple[str, str] | None:
    for cell in cells:
        link = extract_link(cell)
        if link:
            return link
    return None


def row_has_url(cells: list[str]) -> bool:
    return extract_link_anywhere(cells) is not None


def extract_status(cell: str) -> str | None:
    if not cell:
        return None
    text = clean_text(cell)
    if STATUS_TOKEN_RE.search(text):
        return text
    return None


def extract_status_anywhere(cells: list[str]) -> str | None:
    for cell in cells:
        status = extract_status(cell)
        if status:
            return status
    return None


def is_online(status_text: str | None) -> bool:
    if not status_text:
        return False
    return bool(re.match(r"^\s*(ONLINE|VALID)\b", status_text, re.IGNORECASE))


def clean_text(cell: str) -> str:
    """Strip markdown escaping/noise from a cell, collapse whitespace."""
    if not cell:
        return ""
    t = cell.strip()
    t = re.sub(r"\\(.)", r"\1", t)  # unescape \_ \* etc.
    t = re.sub(r"\s+", " ", t)
    return t.strip(" -|")


def strip_used_link(cell: str, url: str) -> str:
    """Remove the matched link's markdown syntax from a cell, keep the rest."""
    t = cell.replace(url, "")
    t = re.sub(r"\[\s*\]\(\s*\)", "", t)
    t = t.replace("[]", "").replace("()", "").replace("<>", "")
    return t


def annotate_status(description: str, status_text: str) -> str:
    """Append a bracketed status qualifier when status isn't a bare ONLINE/VALID
    (e.g. "ONLINE (Backup)" -> "... [ONLINE (Backup)]"), per spec."""
    norm = clean_text(status_text)
    if norm.upper() not in ("ONLINE", "VALID"):
        tag = f"[{norm}]"
        return f"{description} {tag}".strip() if description else tag
    return description


def join_desc(*parts: str) -> str:
    bits = [p.strip() for p in parts if p and p.strip()]
    return " - ".join(bits)


# --------------------------------------------------------------------------
# Per-category row parsers
# --------------------------------------------------------------------------
# Each parser takes the raw cell list of one table row (already known to
# contain at least one URL and not be a separator) and returns a dict
# {"indicator", "category", "description"} or None to drop the row.
# Offline/expired/etc rows return None too; `stats` is updated by the caller.


def parse_forum_or_markets(cells: list[str], category: str, stats: Stats) -> dict | None:
    # Expected: [Name](url) | Status | (optional) description/telegram link
    name_cell = cells[0] if len(cells) > 0 else ""
    status_cell = cells[1] if len(cells) > 1 else ""
    desc_cell = cells[2] if len(cells) > 2 else ""

    link = extract_link(name_cell) or extract_link_anywhere(cells)
    if not link:
        stats.no_url_skipped += 1
        return None
    name_text, url = link

    status = extract_status(status_cell) or extract_status_anywhere(cells)
    if not status:
        stats.no_status_skipped += 1
        return None
    if not is_online(status):
        stats.offline_skipped += 1
        return None

    extra = clean_text(desc_cell)
    description = join_desc(clean_text(name_text), extra)
    description = annotate_status(description, status)
    return {"indicator": url, "category": category, "description": description}


def parse_telegram_threat_actors(cells: list[str], category: str, stats: Stats) -> dict | None:
    # Telegram(url) | Status | Threat Actor Name | Type of attacks
    link_cell = cells[0] if len(cells) > 0 else ""
    status_cell = cells[1] if len(cells) > 1 else ""
    name_cell = cells[2] if len(cells) > 2 else ""
    attack_cell = cells[3] if len(cells) > 3 else ""

    link = extract_link(link_cell) or extract_link_anywhere(cells)
    if not link:
        stats.no_url_skipped += 1
        return None
    _, url = link

    status = extract_status(status_cell) or extract_status_anywhere(cells)
    if not status:
        stats.no_status_skipped += 1
        return None
    if not is_online(status):
        stats.offline_skipped += 1
        return None

    name_text = clean_text(name_cell)
    attack_text = clean_text(attack_cell)
    desc_bits = []
    if name_text:
        desc_bits.append(name_text)
    if attack_text:
        desc_bits.append(f"Type of attacks: {attack_text}")
    description = " | ".join(desc_bits)
    description = annotate_status(description, status)
    return {"indicator": url, "category": category, "description": description}


def parse_telegram_infostealer(cells: list[str], category: str, stats: Stats) -> dict | None:
    # URL | Status | Name
    link_cell = cells[0] if len(cells) > 0 else ""
    status_cell = cells[1] if len(cells) > 1 else ""
    name_cell = cells[2] if len(cells) > 2 else ""

    link = extract_link(link_cell) or extract_link_anywhere(cells)
    if not link:
        stats.no_url_skipped += 1
        return None
    _, url = link

    status = extract_status(status_cell) or extract_status_anywhere(cells)
    if not status:
        stats.no_status_skipped += 1
        return None
    if not is_online(status):
        stats.offline_skipped += 1
        return None

    description = annotate_status(clean_text(name_cell), status)
    return {"indicator": url, "category": category, "description": description}


def parse_twitter_threat_actors(cells: list[str], category: str, stats: Stats) -> dict | None:
    # link | description | category(source) | status
    link_cell = cells[0] if len(cells) > 0 else ""
    desc_cell = cells[1] if len(cells) > 1 else ""
    src_cat_cell = cells[2] if len(cells) > 2 else ""
    status_cell = cells[3] if len(cells) > 3 else (cells[-1] if cells else "")

    link = extract_link(link_cell) or extract_link_anywhere(cells)
    if not link:
        stats.no_url_skipped += 1
        return None
    _, url = link

    status = extract_status(status_cell) or extract_status_anywhere(cells)
    if not status:
        stats.no_status_skipped += 1
        return None
    if not is_online(status):
        stats.offline_skipped += 1
        return None

    desc_text = clean_text(desc_cell)
    src_cat_text = clean_text(src_cat_cell)
    desc_bits = []
    if desc_text:
        desc_bits.append(desc_text)
    if src_cat_text and not STATUS_TOKEN_RE.fullmatch(src_cat_text):
        desc_bits.append(f"Type: {src_cat_text}")
    description = " - ".join(desc_bits)
    description = annotate_status(description, status)
    return {"indicator": url, "category": category, "description": description}


def parse_ransomware_gang(cells: list[str], category: str, stats: Stats) -> dict | None:
    # Columns vary a lot (user:pass, related comms, mirrors...). We take
    # the FIRST url found anywhere in the row as the indicator (per
    # confirmed spec) and shove everything else into description.
    link = extract_link_anywhere(cells)
    if not link:
        stats.no_url_skipped += 1
        return None
    link_text, url = link

    status = extract_status_anywhere(cells)
    if not status:
        stats.no_status_skipped += 1
        return None
    if not is_online(status):
        stats.offline_skipped += 1
        return None

    status_text_clean = clean_text(status)
    remainder_bits = []
    link_name = clean_text(link_text)
    if link_name:
        remainder_bits.append(link_name)
    consumed_link = False
    for cell in cells:
        text_clean = clean_text(cell)
        if text_clean == status_text_clean:
            # This is the status cell itself (whether "ONLINE" or something
            # richer like "ONLINE (Backup)") — already surfaced via
            # annotate_status below, don't duplicate it in the body.
            continue
        if not consumed_link and url in cell:
            # Already captured via link_text above; anything left in this
            # same cell beyond the [text](url) pair (rare) still gets a
            # chance via the generic strip below.
            leftover = clean_text(strip_used_link(cell, url))
            leftover = re.sub(r"[\[\]]", "", leftover).strip(" -")
            if leftover and leftover != link_name and not STATUS_TOKEN_RE.fullmatch(leftover):
                remainder_bits.append(leftover)
            consumed_link = True
            continue
        if not text_clean or STATUS_TOKEN_RE.fullmatch(text_clean):
            continue
        remainder_bits.append(text_clean)

    description = " - ".join(dict.fromkeys(remainder_bits))  
    description = annotate_status(description, status)
    return {"indicator": url, "category": category, "description": description}


PARSERS: dict[str, Callable[[list[str], str, Stats], dict | None]] = {
    "forum": parse_forum_or_markets,
    "markets": parse_forum_or_markets,
    "telegram_threat_actors": parse_telegram_threat_actors,
    "telegram_infostealer": parse_telegram_infostealer,
    "twitter_threat_actors": parse_twitter_threat_actors,
    "ransomware_gang": parse_ransomware_gang,
}


def process_markdown(md_text: str, category: str) -> list[dict]:
    parser = PARSERS[category]
    stats = Stats()
    entries: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for cells in iter_table_rows(md_text):
        if is_separator_row(cells):
            continue
        stats.table_rows_seen += 1
        if not row_has_url(cells):
            stats.no_url_skipped += 1
            continue
        result = parser(cells, category, stats)
        if result is None:
            continue
        key = (result["category"], result["indicator"].lower())
        if key in seen:
            continue
        seen.add(key)
        entries.append(result)
        stats.kept += 1

    print(
        f"[{category}] rows={stats.table_rows_seen} kept={stats.kept} "
        f"offline_skipped={stats.offline_skipped} "
        f"no_url_skipped={stats.no_url_skipped} "
        f"no_status_skipped={stats.no_status_skipped}",
        file=sys.stderr,
    )
    return entries


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------


def http_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    return s


def has_recent_upstream_commit(session: requests.Session) -> bool:
    """Freshness gate: True if ANY of the 6 target files changed upstream
    within LOOKBACK_HOURS. Uses the unauthenticated GitHub REST API
    (no token) purely to read commit metadata — never to fetch content."""
    since = (datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    for category, path in TARGET_FILES.items():
        params = {"path": path, "sha": BRANCH, "since": since, "per_page": 1}
        try:
            resp = session.get(COMMITS_API_TMPL, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            print(f"WARNING: commit check failed for {path}: {exc}", file=sys.stderr)
            continue
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            print(
                "WARNING: GitHub API rate-limited on the unauthenticated "
                "commit check; proceeding as if there were new commits.",
                file=sys.stderr,
            )
            return True
        resp.raise_for_status()
        commits = resp.json()
        if commits:
            print(f"New upstream commit detected for {path}.", file=sys.stderr)
            return True
    return False


def download_raw(session: requests.Session, path: str) -> str:
    url = RAW_URL_TMPL.format(path=path)
    resp = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
    resp.raise_for_status()
    content = resp.content
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"{path} exceeds the {MAX_FILE_BYTES} byte safety cap")
    return content.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def build_dataset(session: requests.Session) -> list[dict]:
    all_entries: list[dict] = []
    for category, path in TARGET_FILES.items():
        md_text = download_raw(session, path)
        all_entries.extend(process_markdown(md_text, category))
    # Stable ordering so the JSON diff (and idempotency check) is meaningful.
    all_entries.sort(key=lambda e: (e["category"], e["indicator"].lower()))
    return all_entries


def build_category_stats(entries: list[dict]) -> dict:
    """Count kept URLs per category. Every known category is present (with 0
    if a file legitimately yielded nothing), in TARGET_FILES order, so the
    output is deterministic and diff-friendly like data.json."""
    counts = {category: 0 for category in TARGET_FILES}
    for entry in entries:
        counts[entry["category"]] = counts.get(entry["category"], 0) + 1
    return {
        "total": len(entries),
        "by_category": counts,
    }


def main() -> int:
    session = http_session()

    try:
        if not has_recent_upstream_commit(session):
            print(
                f"No commits on the target files in the last {LOOKBACK_HOURS}h. "
                "Nothing to do.",
                file=sys.stderr,
            )
            return 0
    except requests.RequestException as exc:
        print(f"ERROR: could not reach GitHub API for commit check: {exc}", file=sys.stderr)
        return 1

    try:
        entries = build_dataset(session)
    except (requests.RequestException, ValueError) as exc:
        print(f"ERROR: failed to build dataset: {exc}", file=sys.stderr)
        return 1

    if not entries:
        print("ERROR: parsed zero entries across all files — refusing to write "
              "an empty data.json (likely an upstream format change).", file=sys.stderr)
        return 1

    new_json = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
    old_json = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else None

    new_stats_json = json.dumps(build_category_stats(entries), indent=2, ensure_ascii=False) + "\n"
    old_stats_json = STATS_PATH.read_text(encoding="utf-8") if STATS_PATH.exists() else None

    if new_json == old_json:
        print("Parsed data is identical to existing data.json. No write needed.", file=sys.stderr)
        return 0

    OUTPUT_PATH.write_text(new_json, encoding="utf-8")
    print(f"Wrote {len(entries)} entries to {OUTPUT_PATH}.", file=sys.stderr)

    if new_stats_json != old_stats_json:
        STATS_PATH.write_text(new_stats_json, encoding="utf-8")
        print(f"Wrote category stats to {STATS_PATH}.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
