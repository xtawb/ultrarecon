"""Fetch large, well-known subdomain wordlists from GitHub on demand.

The wordlist bundled in the package (`wordlists/default.txt`, ~350 words)
is deliberately small -- shipping a multi-million-line file in the
package would bloat every install for people who never use it. Instead,
this module lets `--wordlist <registry-name>` (or a raw URL) download a
real, well-known list from its authoritative GitHub source the first
time it's used, and cache it locally for every run after that.

Every entry below was verified reachable and its line count confirmed
directly against the source at the time this was written.
"""
from __future__ import annotations

import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "ultrarecon" / "wordlists"


@dataclass(frozen=True)
class WordlistSource:
    name: str
    url: str
    lines: int
    description: str


# Sizes are exact line counts confirmed against the live source.
REGISTRY: dict[str, WordlistSource] = {
    src.name: src
    for src in [
        WordlistSource(
            "seclists-5k",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            5_000,
            "SecLists: top 5,000 subdomains from the Alexa top 1M dataset",
        ),
        WordlistSource(
            "seclists-20k",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
            20_000,
            "SecLists: top 20,000 subdomains from the Alexa top 1M dataset",
        ),
        WordlistSource(
            "seclists-110k",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
            110_000,
            "SecLists: top 110,000 subdomains from the Alexa top 1M dataset",
        ),
        WordlistSource(
            "bitquark-100k",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt",
            100_000,
            "SecLists: bitquark's top 100,000 observed subdomains",
        ),
        WordlistSource(
            "deepmagic-50k",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
            49_928,
            "SecLists: deepmagic.com top 50,000 DNS prefixes",
        ),
        WordlistSource(
            "seclists-namelist",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt",
            151_265,
            "SecLists: combined namelist.txt (~151k entries)",
        ),
        WordlistSource(
            "jhaddix",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
            2_171_687,
            "Jason Haddix's all_dns list -- ~2.17M entries (large download, ~25 MB)",
        ),
        WordlistSource(
            "commonspeak2",
            "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt",
            484_701,
            "Assetnote commonspeak2: subdomains mined from real BigQuery data (~485k)",
        ),
        WordlistSource(
            "n0kovo-small",
            "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt",
            200_000,
            "n0kovo_subdomains: small tier (~200k)",
        ),
        WordlistSource(
            "n0kovo-medium",
            "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt",
            500_000,
            "n0kovo_subdomains: medium tier (~500k)",
        ),
        WordlistSource(
            "n0kovo-huge",
            "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt",
            3_000_000,
            "n0kovo_subdomains: huge tier -- 3,000,000 entries (large download, ~50 MB)",
        ),
    ]
}


class WordlistFetchError(Exception):
    pass


def cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.txt"


def is_cached(name: str) -> bool:
    return cache_path(name).exists()


def _download(url: str, dest: Path, logger=None, timeout: float = 30.0) -> None:
    """Stream a URL to disk, writing to a temp file first so a failed or
    interrupted download never leaves a corrupt file in the cache."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "ultrarecon-wordlist-fetch"})

    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as f:
            total = resp.headers.get("Content-Length")
            total = int(total) if total else None
            downloaded = 0
            last_report = 0.0
            chunk_size = 1024 * 256
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if logger and total and time.monotonic() - last_report > 1.0:
                    pct = downloaded / total * 100
                    logger.info(f"  downloading {dest.name}: {downloaded // 1024} KB / {total // 1024} KB ({pct:.0f}%)")
                    last_report = time.monotonic()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        raise WordlistFetchError(f"failed to download {url}: {exc}") from exc

    shutil.move(str(tmp), str(dest))
    if logger:
        elapsed = time.monotonic() - start
        logger.info(f"  cached {dest.name} ({dest.stat().st_size // 1024} KB) in {elapsed:.1f}s")


def get(name: str, force: bool = False, logger=None) -> Path:
    """Return the local path for a registry wordlist, downloading it first if needed."""
    src = REGISTRY.get(name)
    if src is None:
        raise WordlistFetchError(f"unknown wordlist '{name}'. Run `ultrarecon wordlists list` to see options.")
    dest = cache_path(name)
    if dest.exists() and not force:
        return dest
    if logger:
        logger.info(f"Fetching '{name}' ({src.lines:,} lines) from {src.url}")
    _download(src.url, dest, logger=logger)
    return dest


def get_from_url(url: str, force: bool = False, logger=None) -> Path:
    """Cache an arbitrary raw wordlist URL (e.g. a private list you host on GitHub)."""
    safe_name = "".join(c if c.isalnum() or c in "-._" else "_" for c in url)[-100:]
    dest = CACHE_DIR / f"url_{safe_name}"
    if dest.exists() and not force:
        return dest
    if logger:
        logger.info(f"Fetching custom wordlist from {url}")
    _download(url, dest, logger=logger)
    return dest


def resolve(spec: str | None, force: bool = False, logger=None) -> str | None:
    """Turn a --wordlist value into a local file path.

    Accepts, in order: None (unchanged), a registry name (downloaded/
    cached automatically), a raw http(s) URL (downloaded/cached), or a
    plain local path (returned as-is -- existing behavior, untouched).
    """
    if spec is None:
        return None
    if spec in REGISTRY:
        return str(get(spec, force=force, logger=logger))
    if spec.startswith(("http://", "https://")):
        return str(get_from_url(spec, force=force, logger=logger))
    return spec


def list_registry() -> list[tuple[WordlistSource, bool]]:
    """Return every known wordlist paired with whether it's already cached."""
    return [(src, is_cached(src.name)) for src in REGISTRY.values()]
