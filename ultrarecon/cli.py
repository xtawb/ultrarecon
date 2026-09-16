from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, wordlist_fetch
from .core import Scanner, ScanOptions, check_availability
from .installer import offer_install
from .sources import ALL_SOURCES, INSTALL_HINTS
from .updater import check_for_update, self_update
from .utils import Palette as P
from .utils import get_logger, is_valid_domain, normalize_domain, which


def _parse_resolvers(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    return [r.strip() for r in raw.split(",") if r.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ultrarecon",
        description=(
            "Multi-phase subdomain enumeration and live-host triage for authorized "
            "security recon: passive sources, DNS bruteforce, and recursive "
            "wildcard-driven deep enumeration in one pipeline."
        ),
    )
    p.add_argument("--version", action="version", version=f"ultrarecon {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="run a reconnaissance scan against a domain",
        description=(
            "Runs one or more recon phases against a domain: passive enumeration "
            "(theHarvester, amass, sublist3r, subfinder, assetfinder, crt.sh, "
            "optionally VirusTotal), DNS bruteforce, and recursive wildcard-driven "
            "deep enumeration -- then resolves, deduplicates, and optionally probes "
            "for live hosts with httpx."
        ),
    )
    scan.add_argument("-d", "--domain", required=True, help="target domain, e.g. example.com or *.example.com")
    scan.add_argument("-o", "--outdir", default=None, help="output directory (default: ./out/<domain>)")

    phases = scan.add_argument_group("recon phases")
    phases.add_argument(
        "--passive", action="store_true",
        help="run passive enumeration sources (default when no phase flag is given)",
    )
    phases.add_argument(
        "--bruteforce", action="store_true",
        help="run DNS subdomain bruteforce using a wordlist",
    )
    phases.add_argument(
        "--deep", action="store_true",
        help="run recursive wildcard-driven deep enumeration under any wildcard "
             "patterns found (e.g. *.testnet.example.com -> bruteforce under "
             "testnet.example.com, recursing into further wildcards up to --max-depth)",
    )
    phases.add_argument("--all", action="store_true", help="run passive + bruteforce + deep")
    phases.add_argument(
        "--only", default=None,
        help=f"limit passive sources to this comma-separated subset: {','.join(ALL_SOURCES)}",
    )
    phases.add_argument("--no-resolve", action="store_true", help="skip the DNS resolution/verification stage")
    phases.add_argument("--no-probe", action="store_true", help="skip the httpx live-host stage")

    dns_opts = scan.add_argument_group("DNS / bruteforce / deep options")
    dns_opts.add_argument(
        "--wordlist", default=None, metavar="PATH|NAME|URL",
        help="wordlist for --bruteforce/--deep: a local file path, the name of a "
             "wordlist from `ultrarecon wordlists list` (auto-downloaded and "
             "cached on first use), or a raw http(s) URL (default: built-in list)",
    )
    dns_opts.add_argument(
        "--concurrency", type=int, default=50, metavar="N",
        help="concurrent DNS queries for bruteforce/deep/resolve (default: 50)",
    )
    dns_opts.add_argument(
        "--dns-timeout", type=float, default=3.0, metavar="SEC",
        help="per-query DNS timeout in seconds (default: 3.0)",
    )
    dns_opts.add_argument(
        "--dns-retries", type=int, default=1, metavar="N",
        help="retries per query on timeout/SERVFAIL (default: 1)",
    )
    dns_opts.add_argument(
        "--resolvers", default=None, metavar="IP,IP,...",
        help="comma-separated custom resolver IPs (requires dnspython; falls back "
             "to the system resolver otherwise)",
    )
    dns_opts.add_argument(
        "--rate-limit", type=float, default=None, metavar="QPS",
        help="cap DNS queries per second across all workers (default: unlimited)",
    )
    dns_opts.add_argument(
        "--max-depth", type=int, default=2, metavar="N",
        help="maximum recursion depth for --deep enumeration (default: 2)",
    )

    httpx_opts = scan.add_argument_group("httpx live-probe options")
    httpx_opts.add_argument("--ports", default="80,443,8080,8000,8888")
    httpx_opts.add_argument("--threads", type=int, default=200, help="httpx thread count (default: 200)")

    misc = scan.add_argument_group("misc")
    misc.add_argument(
        "-y", "--yes", action="store_true",
        help="auto-confirm prompts (install missing tools, apply updates) without asking",
    )
    misc.add_argument(
        "--no-install-prompt", action="store_true",
        help="never offer to install missing tools; just skip them",
    )
    misc.add_argument("--no-update-check", action="store_true", help="skip the startup update check")
    misc.add_argument("-v", "--verbose", action="store_true", help="verbose (debug-level) logging")
    misc.add_argument("-q", "--quiet", action="store_true", help="only show warnings and errors")
    misc.add_argument("--debug", action="store_true", help="alias for --verbose")

    check = sub.add_parser("check", help="show which enumeration sources are available")
    check.add_argument("-y", "--yes", action="store_true", help="auto-confirm installing missing tools")
    check.add_argument("--install", action="store_true", help="offer to install any missing tools")

    update = sub.add_parser("update", help="check for a newer release and optionally install it")
    update.add_argument("-y", "--yes", action="store_true", help="apply the update without asking")

    wordlists = sub.add_parser(
        "wordlists",
        help="browse and fetch large subdomain wordlists from GitHub",
        description=(
            "Manage the wordlists usable with `scan --wordlist`. The bundled "
            "default list is small on purpose; real large lists (SecLists, "
            "n0kovo_subdomains, commonspeak2 -- up to millions of entries) are "
            "fetched from their authoritative GitHub sources on demand and "
            f"cached under {wordlist_fetch.CACHE_DIR}."
        ),
    )
    wl_sub = wordlists.add_subparsers(dest="wordlists_command", required=True)
    wl_sub.add_parser("list", help="show every available wordlist and whether it's cached")
    wl_get = wl_sub.add_parser("get", help="download (or re-download) a wordlist into the cache")
    wl_get.add_argument("name", help="registry name (see `ultrarecon wordlists list`) or a raw http(s) URL")
    wl_get.add_argument("--force", action="store_true", help="re-download even if already cached")

    sub.add_parser("version", help="print the version and exit")
    return p


def maybe_notify_update() -> None:
    """Best-effort, non-blocking notice -- never delays or breaks a scan."""
    available, latest = check_for_update(timeout=3)
    if available:
        print(
            P.yellow(
                f"\nA newer version is available: {latest} (you have {__version__}). "
                f"Run `ultrarecon update` to upgrade.\n"
            )
        )


def cmd_check(args: argparse.Namespace) -> int:
    print(P.bold("Source availability:"))
    avail = check_availability()
    for name, ok in avail.items():
        status = P.green("available") if ok else P.red("unavailable")
        print(f"  [{status:>20}]  {name}")
        if not ok:
            print(f"      {P.dim('install: ' + INSTALL_HINTS[name])}")

    if args.install:
        missing = [name for name, ok in avail.items() if not ok and name != "virustotal"]
        offer_install(missing, assume_yes=args.yes)
    return 0


def cmd_wordlists(args: argparse.Namespace) -> int:
    if args.wordlists_command == "list":
        print(P.bold("Available wordlists:"))
        print(f"{P.dim(f'Cache directory: {wordlist_fetch.CACHE_DIR}')}\n")
        for src, cached in wordlist_fetch.list_registry():
            status = P.green("cached") if cached else P.dim("not downloaded")
            print(f"  {src.name:<20} {src.lines:>10,} lines  [{status}]")
            print(f"    {P.dim(src.description)}")
        print(f"\nFetch one with: {P.bold('ultrarecon wordlists get <name>')}")
        print(f"Use it directly with: {P.bold('ultrarecon scan -d example.com --bruteforce --wordlist <name>')}")
        return 0

    if args.wordlists_command == "get":
        logger = get_logger()
        try:
            if args.name.startswith("http://") or args.name.startswith("https://"):
                path = wordlist_fetch.get_from_url(args.name, force=args.force, logger=logger)
            else:
                path = wordlist_fetch.get(args.name, force=args.force, logger=logger)
        except wordlist_fetch.WordlistFetchError as exc:
            print(P.red(str(exc)), file=sys.stderr)
            return 1
        print(P.green(f"Ready: {path}"))
        return 0

    return 1


def cmd_update(args: argparse.Namespace) -> int:
    print("Checking for updates...")
    available, latest = check_for_update(timeout=10)
    if not available:
        print(P.green(f"You're already on the latest version ({__version__})."))
        return 0

    print(P.yellow(f"New version available: {latest} (current: {__version__})"))
    if not args.yes:
        try:
            answer = input(P.bold("Update now? [y/N]: ")).strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print(P.dim("Skipped."))
            return 0

    if not which("pip") and not which("pip3"):
        print(P.red("pip not found -- cannot self-update automatically."))
        return 1

    print("Updating...")
    ok, message = self_update()
    if ok:
        print(P.green(f"Updated successfully: {message}"))
        return 0
    print(P.red(f"Update failed: {message}"))
    return 1


def _resolve_phases(args: argparse.Namespace) -> tuple[bool, bool, bool]:
    if args.all:
        return True, True, True
    any_given = args.passive or args.bruteforce or args.deep
    if any_given:
        return args.passive, args.bruteforce, args.deep
    return True, False, False  # backward-compatible default: passive only


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.no_update_check:
        maybe_notify_update()

    domain = normalize_domain(args.domain)
    if not is_valid_domain(domain):
        print(P.red(f"'{args.domain}' does not look like a valid domain."), file=sys.stderr)
        return 2

    if args.concurrency <= 0:
        print(P.red("--concurrency must be a positive integer."), file=sys.stderr)
        return 2
    if args.max_depth < 0:
        print(P.red("--max-depth must be zero or a positive integer."), file=sys.stderr)
        return 2

    passive, bruteforce, deep = _resolve_phases(args)

    sources = (
        [s.strip().lower() for s in args.only.split(",")]
        if args.only else list(ALL_SOURCES)
    )
    sources = [s for s in sources if s in ALL_SOURCES]
    if passive and not sources:
        print(P.red("No valid sources selected for passive enumeration."), file=sys.stderr)
        return 2

    if passive and not args.no_install_prompt:
        avail = check_availability()
        missing = [s for s in sources if s in avail and not avail[s] and s != "virustotal"]
        if missing:
            offer_install(missing, assume_yes=args.yes)

    wordlist_path = args.wordlist
    if (bruteforce or deep) and args.wordlist:
        try:
            wordlist_path = wordlist_fetch.resolve(args.wordlist, logger=get_logger())
        except wordlist_fetch.WordlistFetchError as exc:
            print(P.red(str(exc)), file=sys.stderr)
            return 1

    outdir = Path(args.outdir) if args.outdir else Path("out") / domain
    opts = ScanOptions(
        domain=domain,
        outdir=outdir,
        sources=sources,
        passive=passive,
        bruteforce=bruteforce,
        deep=deep,
        resolve=not args.no_resolve,
        probe_alive=not args.no_probe,
        ports=args.ports,
        threads=args.threads,
        wordlist=wordlist_path,
        concurrency=args.concurrency,
        dns_timeout=args.dns_timeout,
        dns_retries=args.dns_retries,
        resolvers=_parse_resolvers(args.resolvers),
        rate_limit=args.rate_limit,
        max_depth=args.max_depth,
        verbose=args.verbose,
        quiet=args.quiet,
        debug=args.debug,
    )
    report = Scanner(opts).run()

    print()
    print(P.bold("Summary"))
    print(f"  Targets           : {report.targets}")
    print(f"  Raw candidates    : {report.total_subdomains}")
    print(f"  Wildcard patterns : {report.wildcards_detected}")
    print(f"  Verified subdomains: {P.bold(str(report.resolved))}")
    print(f"  Alive (HTTP/S)    : {report.alive}")
    print(f"  Errors            : {report.errors}")
    total_time = sum(report.phases.values())
    print(f"  Total time        : {total_time:.1f}s")
    print(f"  Report            : {outdir / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return cmd_check(args)
    if args.command == "update":
        return cmd_update(args)
    if args.command == "wordlists":
        return cmd_wordlists(args)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "scan":
        return cmd_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
