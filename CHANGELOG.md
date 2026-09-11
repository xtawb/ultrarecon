# Changelog

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
