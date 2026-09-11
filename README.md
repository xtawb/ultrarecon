# UltraRecon

Parallel subdomain enumeration and live-host triage for authorized security
recon — one command instead of a text file full of copy-pasted shell lines.

UltraRecon orchestrates the tools most bug bounty hunters already use
(theHarvester, amass, sublist3r, subfinder, assetfinder, crt.sh), runs them
concurrently, merges and de-duplicates the results, filters out DNS noise
(wildcard catch-alls, dead records), and hands what's left to `httpx` for a
live-host + tech-stack sweep. It ends with a single Markdown/JSON report
instead of a folder full of loose `.txt` files.

Based on the methodology described in
[*Recon Methodology: Subdomain Enumeration*](https://medium.com/@marduk.i.am/recon-methodology-subdomain-enumeration-0e0493001a03)
by Marduk I Am, automated and extended.

## Why this instead of a shell script

- **Runs sources concurrently**, not one after another — a full sweep takes
  as long as the slowest tool, not the sum of all of them.
- **No `jq` dependency.** The crt.sh and theHarvester-JSON parsing are done
  in pure Python.
- **Wildcard DNS detection.** Targets with catch-all DNS records make every
  guessed subdomain look "alive." UltraRecon probes for this first and
  filters accordingly, instead of reporting hundreds of false positives.
- **Resilient to flaky upstreams.** crt.sh is a single, heavily-shared
  community server that returns 429/502/503 under load; UltraRecon retries
  with exponential backoff instead of treating that as a hard failure.
- **One report, not five text files.** `report.md` / `report.json` summarize
  per-source counts, resolved hosts, and live hosts in one place.
- **Fails gracefully.** Missing tools are skipped (with an install hint),
  never crash the run.

## Installation

```bash
git clone https://github.com/xtawb/ultrarecon.git
cd ultrarecon
pip install -e .
```

UltraRecon itself has **zero required third-party Python dependencies** —
it only needs a standard Python 3.10+ interpreter. What it *orchestrates*
are the external recon tools below, each optional (missing ones are simply
skipped):

| Tool | Purpose | Install |
|---|---|---|
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT: hosts, emails, ASNs, IPs | `pip install theHarvester` |
| [amass](https://github.com/owasp-amass/amass) | Active + passive subdomain enum | `snap install amass` |
| [sublist3r](https://github.com/aboul3la/Sublist3r) | Passive subdomain enum | `pip install sublist3r` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Passive subdomain enum | `go install github.com/tomnomnom/assetfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live-host probing, tech-detect | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| crt.sh | Certificate-transparency lookup | built in, no install needed |
| VirusTotal *(optional)* | Passive subdomain enum | set `VT_API_KEY` env var |

Check what's currently available on your system at any time:

```bash
ultrarecon check
```

## Usage

```bash
# Full scan: every available source, DNS resolution, httpx live-probe
ultrarecon scan -d example.com

# Wildcard input is accepted and normalized automatically
ultrarecon scan -d "*.example.com"

# Only run specific sources
ultrarecon scan -d example.com --only subfinder,amass,crtsh

# Skip the DNS resolution or the httpx stage
ultrarecon scan -d example.com --no-resolve
ultrarecon scan -d example.com --no-probe

# Custom output directory, ports, and thread count
ultrarecon scan -d example.com -o ./results --ports 80,443,8443 --threads 300
```

### Output layout

```
out/example.com/
├── 0_amass.txt                 # raw per-source output
├── 0_subfinder.txt
├── 0_crtsh.txt
├── ...
├── theharvester_emails.txt      # OSINT extras from theHarvester
├── theharvester_asns.txt
├── theharvester_ips.txt
├── 1_subdomains.txt             # merged, de-duplicated master list
├── 2_subdomains_resolved.txt    # DNS-resolvable subset
├── 1_subdomains_alive.txt       # live over HTTP/HTTPS (httpx)
├── 1_subdomains_alive_info.txt  # + status code, title, tech stack
├── report.json
└── report.md
```

## Architecture

```
ultrarecon/
├── sources.py     # one adapter class per enumeration source
├── resolver.py     # wildcard detection + concurrent DNS resolution
├── probe.py        # httpx wrapper (alive + tech-detect)
├── report.py        # JSON / Markdown report generation
├── core.py          # orchestrator: runs sources concurrently, merges, reports
└── cli.py            # argparse entry point (scan / check / version)
```

Adding a new source means writing one small subclass of `Source` in
`sources.py` and registering it in `ALL_SOURCES` — the orchestrator, CLI,
and report all pick it up automatically.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
ruff check ultrarecon tests
```

## Legal

This tool automates **passive and semi-passive reconnaissance** — it does
not exploit anything. Even so, you are responsible for only pointing it at
domains you are authorized to test: an in-scope bug bounty / VDP target, or
infrastructure you own. Scanning domains without authorization may violate
computer-crime laws in your jurisdiction. The authors accept no liability
for misuse.

## License

MIT — see [LICENSE](LICENSE).
