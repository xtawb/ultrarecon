# Changelog

## [1.3.0] - 2026-09-16
### Added
- **Large wordlist support from GitHub** (`ultrarecon wordlists`): `--wordlist`
  now accepts a registry name or a raw http(s) URL, not just a local path.
  Eleven well-known, verified wordlists (SecLists, n0kovo_subdomains,
  Assetnote commonspeak2 -- from 5,000 up to 3,000,000 lines) are fetched
  from their authoritative GitHub sources on first use and cached under
  `~/.cache/ultrarecon/wordlists/`. New subcommands: `ultrarecon wordlists
  list` and `ultrarecon wordlists get <name> [--force]`.
- Downloads stream to a temp file and are only moved into the cache on
  success, so an interrupted download never leaves a corrupt cached file.
- 15 new tests (`test_wordlist_fetch.py` + CLI parsing tests) -- 76 total,
  up from 62.

### Notes
- Existing `--wordlist path/to/file.txt` behavior is completely
  unchanged -- registry names and URLs are additive, resolved before the
  existing local-file loading logic even runs.
- Verified live: downloaded `seclists-5k` and `seclists-20k` for real,
  confirmed exact line counts, and ran a real bruteforce scan against
  python.org with an auto-fetched wordlist (found 17 real subdomains).

## [1.2.1] - 2026-09-16
### Fixed
- `ultrarecon update` failed outright on PEP 668 "externally managed
  environment" systems (Kali, Debian, etc.) with `error:
  externally-managed-environment`, even though `installer.py` already had
  the `--break-system-packages` retry fallback for individual tools --
  `updater.self_update()` had never gotten the same treatment. It now
  retries with `--break-system-packages` exactly like tool installation
  does, reported live by a user hitting it on Kali.

## [1.2.0] - 2026-09-16
### Added
- **DNS subdomain bruteforce** (`--bruteforce`): wordlist-driven, concurrent,
  configurable timeout/retries/rate-limit/custom-resolvers, with a built-in
  default wordlist (`--wordlist` to use your own).
- **Recursive, wildcard-driven deep enumeration** (`--deep`, `--max-depth`):
  treats a wildcard pattern like `*.testnet.example.com` as an enumeration
  target rather than a literal hostname -- extracts the base domain,
  bruteforces under it, and recurses into any further wildcard patterns
  actually observed in the data, bounded by `--max-depth`.
- **Escaped-domain parsing**: entries like `*.preview\.origin.arc.io`
  (DNS presentation-format escaped dots) are normalized to
  `preview.origin.arc.io` before resolution -- new `patterns.py` module.
- **Auto-detection of wildcard patterns from existing output files**: if
  `1_subdomains.txt` / `wildcards.txt` already exist in the output
  directory from a previous run, `--deep` picks them up automatically for
  any target, without hardcoding domain names.
- **Phase-based CLI**: `--passive`, `--bruteforce`, `--deep`, `--all`,
  composable and backward compatible (`ultrarecon scan -d example.com`
  with no phase flag still behaves exactly like earlier releases --
  passive only).
- New DNS/bruteforce/deep options: `--wordlist`, `--concurrency`,
  `--dns-timeout`, `--dns-retries`, `--resolvers`, `--rate-limit`,
  `--max-depth`.
- New logging options: `-q`/`--quiet`, `--debug` (alias for `--verbose`).
- Rebuilt DNS engine (`dns_engine.py`) with proper NXDOMAIN / SERVFAIL /
  timeout classification via `dnspython`, transparent fallback to stdlib
  `socket` if it isn't installed, and a shared rate limiter.
- New output files: `wildcards.txt` (wildcard patterns, kept separate
  from verified hostnames) and `0_all_candidates.txt` (raw pre-resolution
  candidate list).
- Phase timings and richer stats (wildcards detected, errors encountered,
  targets) in `report.json` / `report.md`.
- New tests: `test_patterns.py`, `test_dns_engine.py`, `test_bruteforce.py`,
  `test_deep.py`, `test_cli.py` (58 tests total, up from 17).

### Changed
- **`1_subdomains.txt` now holds verified (DNS-resolved) subdomains only**,
  not the raw pre-resolution merge. This is a documented behavior change
  requested to make "verified" mean what it says; the previous raw-merge
  behavior is preserved as `0_all_candidates.txt`, and
  `2_subdomains_resolved.txt` is kept for backward compatibility with the
  same content as `1_subdomains.txt`.
- `dnspython` is now a runtime dependency (installed automatically) for
  accurate DNS status classification and custom-resolver support; the
  tool still runs without it via a `socket`-based fallback.
- `resolver.detect_wildcard()` now returns a **set** of wildcard IPs
  instead of a single IP string, and requires every probe to resolve
  (not that they all match one exact address). This fixes a real false
  negative found during testing: CDN-fronted wildcards (Cloudflare,
  Fastly, CloudFront, ...) commonly rotate between several IPs, so the
  old "all probes must return the identical IP" check silently missed
  them and let hundreds of false-positive subdomains through.

### Fixed
- Version metadata was inconsistent between `ultrarecon/__init__.py` and
  `pyproject.toml` after the 1.1.0 release (the latter was never bumped).
  Both now read 1.2.0.

## [1.1.0] - 2026-09-11
### Added
- `ultrarecon update` command: checks GitHub Releases for a newer version
  and can self-update in place via `pip install --upgrade git+...`.
- Non-blocking update notice printed automatically at the start of `scan`
  (disable with `--no-update-check`).
- Interactive "install missing tools now?" prompt when a requested source
  isn't installed, with a real installer (not just a hint) for pip/go/snap
  -based tools. Auto-confirm with `-y`/`--yes`, or disable entirely with
  `--no-install-prompt`.
- Automatic retry with `--break-system-packages` on PEP 668
  "externally managed environment" pip errors.
- `ultrarecon check --install` to audit *and* fix tool availability in one step.

### Fixed
- The PyPI `theHarvester` package is a stale, unmaintained stub (`0.0.1`)
  that does **not** install the real tool. The installer and docs now point
  to `pip install git+https://github.com/laramies/theHarvester.git` instead.

## [1.0.0] - 2026-09-11
### Added
- Initial public release.
- Parallel adapters for theHarvester, amass, sublist3r, subfinder, assetfinder.
- Native (dependency-free) crt.sh certificate-transparency source with
  exponential backoff for upstream 429/500/502/503/504 responses.
- Optional VirusTotal source, enabled via `VT_API_KEY`.
- Wildcard DNS detection to filter catch-all false positives.
- Concurrent DNS resolution stage before HTTP probing.
- httpx-based live-host probing with status/title/tech-detect enrichment.
- JSON and Markdown scan reports.
- `ultrarecon check` command to audit local tool availability with
  install hints.
- Test suite (pytest) and GitHub Actions CI matrix (3.10–3.12).
