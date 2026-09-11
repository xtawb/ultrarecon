"""Install missing external recon tools on request.

This never runs silently — it only acts after the user explicitly
confirms (or passes --yes on the CLI). Each tool has one "best effort"
install command; anything it can't handle automatically (e.g. amass
needs snap or a Go toolchain that may not be present) falls back to
printing the manual instructions instead of guessing further.
"""
from __future__ import annotations

import sys

from .utils import Palette as P
from .utils import run, which

# One well-known, non-interactive install command per tool. `sudo` is only
# used for snap, which is genuinely a system package manager operation.
AUTO_INSTALL_COMMANDS: dict[str, str] = {
    # NOTE: the "theHarvester" package on PyPI is a stale, unmaintained stub
    # (last published as 0.0.1) — installing it does NOT give you the real
    # tool. The upstream project is only distributed via apt (Kali), pipx,
    # or a git checkout, so we install straight from the GitHub repo instead.
    "theharvester": f"{sys.executable} -m pip install --user "
                     "'git+https://github.com/laramies/theHarvester.git'",
    "sublist3r": f"{sys.executable} -m pip install --user sublist3r",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
}

# amass needs a package manager decision (snap vs go); resolved at runtime.
def _amass_command() -> str | None:
    if which("snap"):
        return "sudo snap install amass"
    if which("go"):
        return "go install -v github.com/owasp-amass/amass/v4/...@master"
    return None


BINARY_NAME = {
    "theharvester": "theHarvester",
    "amass": "amass",
    "sublist3r": "sublist3r",
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "httpx": "httpx",
}

NEEDS_GO = {"subfinder", "assetfinder", "httpx"}


def build_command(tool: str) -> str | None:
    if tool == "amass":
        return _amass_command()
    return AUTO_INSTALL_COMMANDS.get(tool)


def install_tool(tool: str) -> tuple[bool, str]:
    if tool in NEEDS_GO and not which("go"):
        return False, "requires the Go toolchain (https://go.dev/dl/) — install Go first"
    cmd = build_command(tool)
    if cmd is None:
        return False, "no automatic installer available for this tool"

    print(P.dim(f"  $ {cmd}"))
    code, out, err = run(cmd, timeout=600)
    binary = BINARY_NAME.get(tool, tool)
    if code == 0 and which(binary):
        return True, "installed"
    if code == 0 and "pip" in cmd:
        return False, (
            "pip reported success but the binary isn't on PATH — "
            "add ~/.local/bin to PATH and retry, or reopen your shell"
        )

    # PEP 668 "externally managed" environments (Debian/Ubuntu, etc.) reject
    # plain `pip install`. Retry once with the standard escape hatch before
    # giving up — this is a well-known, deliberate override, not a hack.
    if "externally-managed-environment" in err and "pip" in cmd:
        fallback_cmd = f"{cmd} --break-system-packages"
        print(P.dim("  externally-managed environment detected, retrying with --break-system-packages"))
        print(P.dim(f"  $ {fallback_cmd}"))
        code, out, err = run(fallback_cmd, timeout=600)
        if code == 0 and which(binary):
            return True, "installed (--break-system-packages)"

    return False, (err.strip() or out.strip() or "install command failed")[:300]


def offer_install(missing: list[str], assume_yes: bool = False) -> list[str]:
    """Prompt (unless assume_yes) to auto-install missing tools.

    Returns the list of tools that are still missing afterward.
    """
    if not missing:
        return []

    print(P.yellow(f"\nMissing tools: {', '.join(missing)}"))
    if not assume_yes:
        try:
            answer = input(P.bold("Install them automatically now? [y/N]: ")).strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print(P.dim("Skipping install — see `ultrarecon check` for manual instructions."))
            return missing

    still_missing = []
    for tool in missing:
        print(P.cyan(f"Installing {tool}..."))
        ok, message = install_tool(tool)
        if ok:
            print(P.green(f"  {tool}: installed successfully"))
        else:
            print(P.red(f"  {tool}: {message}"))
            still_missing.append(tool)
    return still_missing
