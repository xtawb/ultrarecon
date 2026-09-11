# Changelog

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
