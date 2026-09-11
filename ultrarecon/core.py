from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from . import probe, resolver
from .report import ScanReport, now_iso
from .sources import ALL_SOURCES, Source
from .utils import Palette as P
from .utils import get_logger, write_lines


@dataclass
class ScanOptions:
    domain: str
    outdir: Path
    sources: list[str]
    resolve: bool = True
    probe_alive: bool = True
    ports: str = "80,443,8080,8000,8888"
    threads: int = 200
    verbose: bool = False


def check_availability() -> dict[str, bool]:
    return {name: cls().available() for name, cls in ALL_SOURCES.items()}


class Scanner:
    def __init__(self, opts: ScanOptions):
        self.opts = opts
        self.log = get_logger(verbose=opts.verbose)
        self.opts.outdir.mkdir(parents=True, exist_ok=True)

    def run(self) -> ScanReport:
        report = ScanReport(domain=self.opts.domain, started_at=now_iso())

        self.log.info(P.bold(f"Target: {self.opts.domain}"))
        wildcard_ip = resolver.detect_wildcard(self.opts.domain)
        if wildcard_ip:
            self.log.warning(
                P.yellow(f"Wildcard DNS detected ({wildcard_ip}) — noisy sources will be sanity-checked")
            )
        report.wildcard_ip = wildcard_ip

        combined: set[str] = set()
        with ThreadPoolExecutor(max_workers=max(len(self.opts.sources), 1)) as pool:
            futures = {}
            for name in self.opts.sources:
                cls = ALL_SOURCES.get(name)
                if cls is None:
                    continue
                source: Source = cls()
                futures[pool.submit(source.run, self.opts.domain, self.opts.outdir)] = name

            for fut in as_completed(futures):
                name = futures[fut]
                result = fut.result()
                report.sources[name] = {
                    "ok": result.ok,
                    "count": len(result.subdomains),
                    "message": result.message or ("ok" if result.ok else ""),
                }
                tag = P.green("done") if result.ok else P.red("skip")
                extra = f" ({len(result.subdomains)} found)" if result.ok else f" — {result.message}"
                self.log.info(f"{name:<12} [{tag}]{extra}")
                combined |= result.subdomains

        combined = {c for c in combined if c.endswith(self.opts.domain)}
        master = self.opts.outdir / "1_subdomains.txt"
        write_lines(master, combined)
        report.total_subdomains = len(combined)
        self.log.info(P.green(f"{len(combined)} unique subdomains") + f" -> {master}")

        if self.opts.resolve and combined:
            self.log.info("Resolving DNS for all candidates...")
            resolved = resolver.resolve_all(combined, workers=self.opts.threads)
            if wildcard_ip:
                # Drop hosts that only resolve to the wildcard catch-all IP —
                # they're DNS noise, not real assets.
                resolved = {h: ip for h, ip in resolved.items() if ip != wildcard_ip}
            resolved_file = self.opts.outdir / "2_subdomains_resolved.txt"
            write_lines(resolved_file, resolved.keys())
            report.resolved = len(resolved)
            self.log.info(P.green(f"{len(resolved)} resolved") + f" -> {resolved_file}")
            target_for_probe = resolved_file if resolved else master
        else:
            target_for_probe = master

        if self.opts.probe_alive and combined:
            self.log.info("Probing live hosts with httpx...")
            alive_file = probe.probe_alive(target_for_probe, self.opts.outdir, self.opts.ports, self.opts.threads)
            if alive_file:
                alive_hosts = alive_file.read_text().splitlines()
                report.alive = len([l for l in alive_hosts if l.strip()])
                self.log.info(P.green(f"{report.alive} alive") + f" -> {alive_file}")
                probe.probe_details(alive_file, self.opts.outdir)
            else:
                self.log.warning(P.yellow("httpx not found — skipping alive probe"))

        report.finished_at = now_iso()
        report.output_dir = str(self.opts.outdir.resolve())
        report.to_json(self.opts.outdir / "report.json")
        report.to_markdown(self.opts.outdir / "report.md")
        return report
