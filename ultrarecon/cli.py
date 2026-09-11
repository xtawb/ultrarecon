from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import Scanner, ScanOptions, check_availability
from .sources import ALL_SOURCES, INSTALL_HINTS
from .utils import Palette as P
from .utils import is_valid_domain, normalize_domain


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ultrarecon",
        description="Parallel subdomain enumeration and live-host triage for authorized recon.",
    )
    p.add_argument("--version", action="version", version=f"ultrarecon {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a full enumeration scan against a domain")
    scan.add_argument("-d", "--domain", required=True, help="target domain, e.g. example.com or *.example.com")
    scan.add_argument("-o", "--outdir", default=None, help="output directory (default: ./out/<domain>)")
    scan.add_argument(
        "--only", default=None,
        help=f"comma-separated sources to use: {','.join(ALL_SOURCES)}",
    )
    scan.add_argument("--no-resolve", action="store_true", help="skip DNS resolution filtering")
    scan.add_argument("--no-probe", action="store_true", help="skip the httpx live-host stage")
    scan.add_argument("--ports", default="80,443,8080,8000,8888")
    scan.add_argument("--threads", type=int, default=200)
    scan.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("check", help="show which enumeration sources are available")

    sub.add_parser("version", help="print the version and exit")
    return p


def cmd_check() -> int:
    print(P.bold("Source availability:"))
    avail = check_availability()
    for name, ok in avail.items():
        status = P.green("available") if ok else P.red("unavailable")
        print(f"  [{status:>20}]  {name}")
        if not ok:
            print(f"      {P.dim('install: ' + INSTALL_HINTS[name])}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    domain = normalize_domain(args.domain)
    if not is_valid_domain(domain):
        print(P.red(f"'{args.domain}' does not look like a valid domain."), file=sys.stderr)
        return 2

    sources = (
        [s.strip().lower() for s in args.only.split(",")]
        if args.only else list(ALL_SOURCES)
    )
    sources = [s for s in sources if s in ALL_SOURCES]
    if not sources:
        print(P.red("No valid sources selected."), file=sys.stderr)
        return 2

    outdir = Path(args.outdir) if args.outdir else Path("out") / domain
    opts = ScanOptions(
        domain=domain,
        outdir=outdir,
        sources=sources,
        resolve=not args.no_resolve,
        probe_alive=not args.no_probe,
        ports=args.ports,
        threads=args.threads,
        verbose=args.verbose,
    )
    report = Scanner(opts).run()

    print()
    print(P.bold("Summary"))
    print(f"  Subdomains found  : {P.bold(str(report.total_subdomains))}")
    print(f"  DNS-resolved      : {P.bold(str(report.resolved))}")
    print(f"  Alive (HTTP/S)    : {P.bold(str(report.alive))}")
    print(f"  Report            : {outdir / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return cmd_check()
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "scan":
        return cmd_scan(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
