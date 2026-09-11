"""Self-update support: check GitHub Releases and optionally upgrade in place.

Kept dependency-free (urllib + subprocess only) so it works the moment the
package is installed, with no extra network library required.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request

from . import __version__

REPO = "xtawb/ultrarecon"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases/latest"
GIT_URL = f"https://github.com/{REPO}.git"


def _parse_version(v: str) -> tuple[int, ...]:
    v = v.strip().lstrip("v")
    parts = []
    for chunk in v.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def fetch_latest_release(timeout: int = 5) -> dict | None:
    """Return the latest release payload, or None if unreachable/none exist."""
    req = urllib.request.Request(
        RELEASES_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ultrarecon-updater"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode(errors="ignore"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def check_for_update(timeout: int = 5) -> tuple[bool, str | None]:
    """Return (update_available, latest_tag). Never raises; fails silently offline."""
    release = fetch_latest_release(timeout=timeout)
    if not release or "tag_name" not in release:
        return False, None
    latest_tag = release["tag_name"]
    return _parse_version(latest_tag) > _parse_version(__version__), latest_tag


def self_update(ref: str = "main") -> tuple[bool, str]:
    """Upgrade the installed package in place via pip + git."""
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{GIT_URL}@{ref}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "updated"
    return False, (proc.stderr.strip() or "pip install failed")[:400]
