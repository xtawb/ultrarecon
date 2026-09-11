from __future__ import annotations

from pathlib import Path

from .utils import run, which


def probe_alive(subdomains_file: Path, workdir: Path, ports: str, threads: int) -> Path | None:
    if not which("httpx"):
        return None
    out = workdir / "1_subdomains_alive.txt"
    _, stdout, _ = run(
        f"httpx -silent -ports {ports} -threads {threads} < {subdomains_file}",
        timeout=900,
    )
    lines = sorted({l.strip() for l in stdout.splitlines() if l.strip()})
    out.write_text("\n".join(lines))
    return out


def probe_details(alive_file: Path, workdir: Path) -> Path | None:
    if not which("httpx") or not alive_file or not alive_file.exists():
        return None
    out = workdir / "1_subdomains_alive_info.txt"
    _, stdout, _ = run(f"httpx -silent -sc -title -tech-detect < {alive_file}", timeout=900)
    out.write_text(stdout)
    return out
