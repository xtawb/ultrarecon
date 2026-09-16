from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path


class Palette:
    """ANSI colors, disabled automatically when stdout isn't a TTY."""

    enabled = sys.stdout.isatty()

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    @classmethod
    def green(cls, t): return cls.wrap("92", t)

    @classmethod
    def red(cls, t): return cls.wrap("91", t)

    @classmethod
    def yellow(cls, t): return cls.wrap("93", t)

    @classmethod
    def cyan(cls, t): return cls.wrap("96", t)

    @classmethod
    def bold(cls, t): return cls.wrap("1", t)

    @classmethod
    def dim(cls, t): return cls.wrap("2", t)


def get_logger(
    name: str = "ultrarecon",
    verbose: bool = False,
    quiet: bool = False,
    debug: bool = False,
) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s %(levelname)-7s %(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        logger.propagate = False

    if debug:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logger.setLevel(level)
    return logger


@contextlib.contextmanager
def phase_timer(store: dict, name: str):
    """Record how long a `with phase_timer(report.phases, 'passive'):` block took."""
    start = time.monotonic()
    try:
        yield
    finally:
        store[name] = round(time.monotonic() - start, 3)


_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(raw: str) -> str:
    """Normalize user input ('*.example.com', 'https://example.com/', ...)."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.lstrip("*.")
    d = d.split("/")[0]
    d = d.split(":")[0]
    return d


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(cmd: str, timeout: int = 900) -> tuple[int, str, str]:
    """Run a shell command and always return (code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except OSError as exc:
        return -1, "", str(exc)


def read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(errors="ignore").splitlines()
        if line.strip()
    }


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.write_text("\n".join(sorted(set(lines))) + "\n" if lines else "")
