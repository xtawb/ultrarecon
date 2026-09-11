"""Adapters around each enumeration source.

Every adapter exposes the same contract:

    result = adapter.run(domain, workdir) -> SourceResult

so the orchestrator (core.py) can treat every tool uniformly, run them
concurrently, and merge whatever comes back without caring how each one
does its job internally.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from .utils import read_lines, run, which


@dataclass
class SourceResult:
    name: str
    ok: bool
    subdomains: set[str] = field(default_factory=set)
    message: str = ""
    artifact: str | None = None


class Source:
    """Base class. Subclasses implement `binary` (or None) and `_execute`."""

    name: str = "base"
    binary: str | None = None  # external executable this source needs

    def available(self) -> bool:
        return self.binary is None or which(self.binary)

    def run(self, domain: str, workdir: Path) -> SourceResult:
        if not self.available():
            return SourceResult(self.name, False, message="binary not found")
        try:
            return self._execute(domain, workdir)
        except Exception as exc:  # noqa: BLE001 — one bad source must never kill the run
            return SourceResult(self.name, False, message=f"unexpected error: {exc}")

    def _execute(self, domain: str, workdir: Path) -> SourceResult:
        raise NotImplementedError


class TheHarvesterSource(Source):
    name = "theharvester"
    binary = "theHarvester"

    def _execute(self, domain, workdir):
        stem = workdir / "raw_theharvester"
        run(f"theHarvester -d {domain} -b all -f {stem}", timeout=600)
        json_path = stem.with_suffix(".json")
        if not json_path.exists():
            return SourceResult(self.name, False, message="no output produced")

        data = json.loads(json_path.read_text(errors="ignore"))
        hosts = set()
        for h in data.get("hosts", []) or []:
            h = h.split(":")[0].strip().lower()
            if h.endswith(domain):
                hosts.add(h)

        # theHarvester surfaces more than hostnames — keep the extras too,
        # they're valuable recon artifacts even outside the subdomain list.
        (workdir / "theharvester_emails.txt").write_text(
            "\n".join(sorted(set(data.get("emails", []) or [])))
        )
        (workdir / "theharvester_asns.txt").write_text(
            "\n".join(sorted(set(data.get("asns", []) or [])))
        )
        (workdir / "theharvester_ips.txt").write_text(
            "\n".join(sorted(set(data.get("ips", []) or [])))
        )
        (workdir / "theharvester_urls.txt").write_text(
            "\n".join(sorted(set(data.get("interesting_urls", []) or [])))
        )
        return SourceResult(self.name, True, hosts, artifact=str(json_path))


class AmassSource(Source):
    name = "amass"
    binary = "amass"

    def _execute(self, domain, workdir):
        out = workdir / "0_amass.txt"
        run(f"amass enum -d {domain} -nocolor -o {out}", timeout=900)
        hosts = read_lines(out)
        return SourceResult(self.name, bool(hosts), hosts, artifact=str(out))


class Sublist3rSource(Source):
    name = "sublist3r"
    binary = "sublist3r"

    def _execute(self, domain, workdir):
        out = workdir / "0_sublist3r.txt"
        run(f"sublist3r -d {domain} -o {out}", timeout=600)
        hosts = read_lines(out)
        return SourceResult(self.name, bool(hosts), hosts, artifact=str(out))


class SubfinderSource(Source):
    name = "subfinder"
    binary = "subfinder"

    def _execute(self, domain, workdir):
        out = workdir / "0_subfinder.txt"
        run(f"subfinder -d {domain} --all --recursive -o {out}", timeout=600)
        hosts = read_lines(out)
        return SourceResult(self.name, bool(hosts), hosts, artifact=str(out))


class AssetfinderSource(Source):
    name = "assetfinder"
    binary = "assetfinder"

    def _execute(self, domain, workdir):
        _, out_text, err = run(f"assetfinder --subs-only {domain}", timeout=300)
        hosts = {l.strip().lower() for l in out_text.splitlines() if l.strip()}
        if not hosts:
            return SourceResult(self.name, False, message=err.strip()[:200] or "no output")
        out = workdir / "0_assetfinder.txt"
        out.write_text("\n".join(sorted(hosts)))
        return SourceResult(self.name, True, hosts, artifact=str(out))


class CrtShSource(Source):
    """Certificate-transparency lookup, implemented natively — no curl/jq."""

    name = "crtsh"
    binary = None
    RETRYABLE: ClassVar[set[int]] = {429, 500, 502, 503, 504}

    def _execute(self, domain, workdir):
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; UltraRecon/1.0)",
                "Accept": "application/json",
            },
        )
        last_err = "unknown error"
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    raw = resp.read().decode(errors="ignore")
                data = json.loads(raw)
                hosts = set()
                for entry in data:
                    for n in entry.get("name_value", "").split("\n"):
                        n = n.strip().lower()
                        if n and not n.startswith("*."):
                            hosts.add(n)
                out = workdir / "0_crtsh.txt"
                out.write_text("\n".join(sorted(hosts)))
                return SourceResult(self.name, True, hosts, artifact=str(out))
            except urllib.error.HTTPError as e:
                last_err = f"HTTP {e.code} from crt.sh (upstream, not local)"
                if e.code not in self.RETRYABLE or attempt == max_attempts - 1:
                    return SourceResult(self.name, False, message=last_err)
            except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
                last_err = str(e)
                if attempt == max_attempts - 1:
                    return SourceResult(self.name, False, message=last_err)
            time.sleep(3 * (2 ** attempt))
        return SourceResult(self.name, False, message=last_err)


class VirusTotalSource(Source):
    """Optional: only runs when VT_API_KEY is set in the environment."""

    name = "virustotal"
    binary = None

    def available(self) -> bool:
        return bool(os.environ.get("VT_API_KEY"))

    def _execute(self, domain, workdir):
        api_key = os.environ["VT_API_KEY"]
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
        hosts: set[str] = set()
        headers = {"x-apikey": api_key}
        while url:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode(errors="ignore"))
            for item in payload.get("data", []):
                host = item.get("id", "").lower()
                if host.endswith(domain):
                    hosts.add(host)
            url = payload.get("links", {}).get("next")
        out = workdir / "0_virustotal.txt"
        out.write_text("\n".join(sorted(hosts)))
        return SourceResult(self.name, bool(hosts), hosts, artifact=str(out))


ALL_SOURCES: dict[str, type[Source]] = {
    "theharvester": TheHarvesterSource,
    "amass": AmassSource,
    "sublist3r": Sublist3rSource,
    "subfinder": SubfinderSource,
    "assetfinder": AssetfinderSource,
    "crtsh": CrtShSource,
    "virustotal": VirusTotalSource,
}

INSTALL_HINTS = {
    "theharvester": "pip install 'git+https://github.com/laramies/theHarvester.git'  (the PyPI 'theHarvester' package is a stale stub — don't use it)",
    "amass": "snap install amass  |  go install github.com/owasp-amass/amass/v4/...@master",
    "sublist3r": "pip install sublist3r",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "crtsh": "built in — no binary required",
    "virustotal": "no binary required — set the VT_API_KEY environment variable",
}
