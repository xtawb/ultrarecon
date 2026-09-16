from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from . import bruteforce as bf
from . import deep as deep_mod
from . import probe, resolver
from .patterns import classify_entries
from .report import ScanReport, now_iso
from .sources import ALL_SOURCES, Source
from .utils import Palette as P
from .utils import get_logger, phase_timer, write_lines


@dataclass
class ScanOptions:
    domain: str
    outdir: Path
    sources: list[str] = field(default_factory=list)

    # phase toggles
    passive: bool = True
    bruteforce: bool = False
    deep: bool = False
    resolve: bool = True
    probe_alive: bool = True

    # httpx (unchanged from earlier versions)
    ports: str = "80,443,8080,8000,8888"
    threads: int = 200

    # DNS engine controls, shared by resolve / bruteforce / deep
    wordlist: str | None = None
    concurrency: int = 50
    dns_timeout: float = 3.0
    dns_retries: int = 1
    resolvers: list[str] | None = None
    rate_limit: float | None = None
    max_depth: int = 2

    # logging
    verbose: bool = False
    quiet: bool = False
    debug: bool = False


def check_availability() -> dict[str, bool]:
    return {name: cls().available() for name, cls in ALL_SOURCES.items()}


def load_existing_output(outdir: Path) -> tuple[set[str], set[str]]:
    """Read a previous run's output in this directory, if any.

    Implements the "auto-detect wildcard patterns already sitting in a
    results file" behavior: works for any target, since it just classifies
    whatever lines are already there rather than assuming a domain name.
    """
    entries: set[str] = set()
    for name in ("1_subdomains.txt", "wildcards.txt", "0_all_candidates.txt"):
        f = outdir / name
        if f.exists():
            entries |= {
                line.strip() for line in f.read_text(errors="ignore").splitlines() if line.strip()
            }
    return classify_entries(entries)


class Scanner:
    def __init__(self, opts: ScanOptions):
        self.opts = opts
        self.log = get_logger(verbose=opts.verbose, quiet=opts.quiet, debug=opts.debug)
        self.opts.outdir.mkdir(parents=True, exist_ok=True)

    def run(self) -> ScanReport:
        o = self.opts
        report = ScanReport(domain=o.domain, started_at=now_iso())
        self.log.info(P.bold(f"Starting reconnaissance for {o.domain}"))

        with phase_timer(report.phases, "wildcard_detection"):
            wildcard_ip = resolver.detect_wildcard(o.domain, resolvers=o.resolvers, timeout=o.dns_timeout)
        if wildcard_ip:
            ip_list = ", ".join(sorted(wildcard_ip))
            self.log.warning(
                P.yellow(f"Wildcard DNS detected on {o.domain} ({ip_list}) -- results will be sanity-checked")
            )
        report.wildcard_ip = sorted(wildcard_ip) if wildcard_ip else None

        raw_entries: set[str] = set()

        # Pick up wildcard patterns / hostnames from a previous run in the
        # same output directory, so deep enumeration can resume/extend it.
        existing_hosts, existing_wildcards = load_existing_output(o.outdir)
        raw_entries |= existing_hosts | existing_wildcards

        # ---------------------------------------------------------------- #
        # Phase 1: passive enumeration (existing sources, unchanged)
        # ---------------------------------------------------------------- #
        if o.passive and o.sources:
            self.log.info("Passive enumeration started")
            with phase_timer(report.phases, "passive"):
                raw_entries |= self._run_passive_sources(report)
            hosts_now, _wc_now = classify_entries(raw_entries)
            self.log.info(P.green(f"Found {len(hosts_now)} subdomains") + " (passive)")

        # ---------------------------------------------------------------- #
        # Phase 2: DNS bruteforce
        # ---------------------------------------------------------------- #
        if o.bruteforce:
            before, _ = classify_entries(raw_entries)
            self.log.info("Bruteforce enumeration started")
            try:
                wordlist = bf.load_wordlist(o.wordlist)
            except bf.WordlistError as exc:
                self.log.error(P.red(f"Bruteforce skipped: {exc}"))
                report.errors += 1
                wordlist = None

            if wordlist:
                with phase_timer(report.phases, "bruteforce"):
                    bf_result = bf.bruteforce(
                        o.domain,
                        wordlist,
                        concurrency=o.concurrency,
                        timeout=o.dns_timeout,
                        retries=o.dns_retries,
                        resolvers=o.resolvers,
                        rate_limit=o.rate_limit,
                        wildcard_ip=wildcard_ip,
                    )
                new_hosts = bf_result.found - before
                raw_entries |= bf_result.found
                report.errors += bf_result.stats.servfail + bf_result.stats.error
                self.log.info(P.green(f"Found {len(new_hosts)} additional subdomains") + " (bruteforce)")
                self.log.debug(
                    f"  bruteforce stats: {bf_result.stats.total} tried, "
                    f"{bf_result.stats.ok} ok, {bf_result.stats.nxdomain} nxdomain, "
                    f"{bf_result.stats.servfail} servfail, {bf_result.stats.timeout} timeout, "
                    f"{bf_result.stats.filtered_wildcard} filtered as wildcard noise"
                )

        # ---------------------------------------------------------------- #
        # Classify what we have so far into real hostnames vs wildcard
        # patterns -- this is what everything downstream operates on.
        # ---------------------------------------------------------------- #
        hostnames, wildcard_patterns = classify_entries(raw_entries)
        report.wildcards_detected = len(wildcard_patterns)
        if wildcard_patterns:
            self.log.info(P.yellow(f"Wildcard patterns detected: {len(wildcard_patterns)}"))

        # ---------------------------------------------------------------- #
        # Phase 3: deep / recursive wildcard-driven enumeration
        # ---------------------------------------------------------------- #
        if o.deep and wildcard_patterns:
            self.log.info("Deep enumeration started")
            try:
                wordlist = bf.load_wordlist(o.wordlist)
            except bf.WordlistError as exc:
                self.log.error(P.red(f"Deep enumeration skipped: {exc}"))
                report.errors += 1
                wordlist = None

            if wordlist:
                with phase_timer(report.phases, "deep"):
                    deep_result = deep_mod.deep_enumerate(
                        wildcard_patterns,
                        wordlist,
                        max_depth=o.max_depth,
                        concurrency=o.concurrency,
                        timeout=o.dns_timeout,
                        retries=o.dns_retries,
                        resolvers=o.resolvers,
                        rate_limit=o.rate_limit,
                        logger=self.log,
                    )
                new_hosts = deep_result.discovered - hostnames
                hostnames |= deep_result.discovered
                for stats in deep_result.per_base_stats.values():
                    report.errors += stats.servfail + stats.error
                self.log.info(
                    P.green(f"Discovered {len(new_hosts)} additional subdomains")
                    + f" (deep, {len(deep_result.visited_bases)} bases, depth {deep_result.depth_reached})"
                )

        # ---------------------------------------------------------------- #
        # Normalize + validate + dedupe
        # ---------------------------------------------------------------- #
        self.log.info("Deduplicating results")
        hostnames = {h for h in hostnames if h.endswith(o.domain)}
        wildcard_patterns = {w for w in wildcard_patterns if w[len("*."):].endswith(o.domain)}

        candidates_file = o.outdir / "0_all_candidates.txt"
        write_lines(candidates_file, hostnames)
        report.total_subdomains = len(hostnames)

        wildcards_file = o.outdir / "wildcards.txt"
        write_lines(wildcards_file, wildcard_patterns)

        master = o.outdir / "1_subdomains.txt"

        # ---------------------------------------------------------------- #
        # Phase 4: resolve -- this is what makes a hostname "verified"
        # ---------------------------------------------------------------- #
        verified = hostnames
        if o.resolve and hostnames:
            with phase_timer(report.phases, "resolve"):
                resolved = resolver.resolve_all(
                    hostnames,
                    workers=o.concurrency,
                    resolvers=o.resolvers,
                    timeout=o.dns_timeout,
                    retries=o.dns_retries,
                    rate_limit=o.rate_limit,
                )
            if wildcard_ip:
                resolved = {h: ip for h, ip in resolved.items() if ip not in wildcard_ip}
            verified = set(resolved.keys())
            # kept for backward compatibility with earlier releases
            write_lines(o.outdir / "2_subdomains_resolved.txt", verified)

        write_lines(master, verified)
        report.resolved = len(verified)
        self.log.info(P.green(f"{len(verified)} unique verified subdomains"))
        self.log.info(f"Results saved to {master}")

        target_for_probe = master

        # ---------------------------------------------------------------- #
        # Phase 5: live-host probing (unchanged from earlier versions)
        # ---------------------------------------------------------------- #
        if o.probe_alive and verified:
            self.log.info("Probing live hosts with httpx...")
            with phase_timer(report.phases, "probe"):
                alive_file = probe.probe_alive(target_for_probe, o.outdir, o.ports, o.threads)
                if alive_file:
                    alive_hosts = alive_file.read_text().splitlines()
                    report.alive = len([l for l in alive_hosts if l.strip()])
                    probe.probe_details(alive_file, o.outdir)
            if alive_file:
                self.log.info(P.green(f"{report.alive} alive") + f" -> {o.outdir / '1_subdomains_alive.txt'}")
            else:
                self.log.warning(P.yellow("httpx not found -- skipping alive probe"))

        report.finished_at = now_iso()
        report.output_dir = str(o.outdir.resolve())
        report.to_json(o.outdir / "report.json")
        report.to_markdown(o.outdir / "report.md")
        return report

    def _run_passive_sources(self, report: ScanReport) -> set[str]:
        o = self.opts
        combined: set[str] = set()
        with ThreadPoolExecutor(max_workers=max(len(o.sources), 1)) as pool:
            futures = {}
            for name in o.sources:
                cls = ALL_SOURCES.get(name)
                if cls is None:
                    continue
                source: Source = cls()
                futures[pool.submit(source.run, o.domain, o.outdir)] = name

            for fut in as_completed(futures):
                name = futures[fut]
                result = fut.result()
                report.sources[name] = {
                    "ok": result.ok,
                    "count": len(result.subdomains),
                    "message": result.message or ("ok" if result.ok else ""),
                }
                if not result.ok:
                    report.errors += 1
                tag = P.green("done") if result.ok else P.red("skip")
                extra = f" ({len(result.subdomains)} found)" if result.ok else f" -- {result.message}"
                self.log.info(f"  {name:<12} [{tag}]{extra}")
                combined |= result.subdomains
        return combined
