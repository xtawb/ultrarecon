# UltraRecon

Multi-phase subdomain enumeration and live-host triage for authorized
security recon — one command instead of a text file full of copy-pasted
shell lines.

UltraRecon runs three complementary recon phases against a domain —
**passive enumeration** (the tools most bug bounty hunters already use),
**DNS bruteforce**, and **recursive, wildcard-driven deep enumeration** —
merges and de-duplicates everything into one verified subdomain list,
filters out DNS noise (wildcard catch-alls, dead records), and hands what's
left to `httpx` for a live-host + tech-stack sweep. It ends with a single
Markdown/JSON report instead of a folder full of loose `.txt` files.

Originally based on the methodology in
[*Recon Methodology: Subdomain Enumeration*](https://medium.com/@marduk.i.am/recon-methodology-subdomain-enumeration-0e0493001a03)
by Marduk I Am, and extended with ideas from
[*Unveiling Hidden Threats: Advanced Recon Techniques*](https://medium.com/@rootspaghetti/unveiling-hidden-threats-advanced-recon-techniques-and-the-path-to-automation-4c1b3dd885a3)
by rootspaghetti — automated, and adapted into UltraRecon's own
architecture rather than copied wholesale.

## Features

- **Three recon phases in one pipeline**: passive sources, DNS bruteforce,
  and recursive wildcard-driven deep enumeration — run any combination.
- **Wildcard-pattern intelligence.** A line like `*.testnet.example.com`
  isn't just stored as text — UltraRecon recognizes it as an enumeration
  *target*, extracts `testnet.example.com`, and bruteforces subdomains
  under it. If that turns up its own wildcard pattern (e.g.
  `*.rpc.testnet.example.com`), it recurses, bounded by `--max-depth`.
- **Escaped-domain aware.** Entries like `*.preview\.origin.arc.io` (a
  DNS presentation-format escaped dot) are normalized to
  `preview.origin.arc.io` before any resolution happens.
- **Real wildcard DNS detection**, robust to CDN IP rotation (Cloudflare,
  Fastly, CloudFront, ...) — probes multiple random non-existent labels
  and treats every IP they resolve to as catch-all noise, not just a
  single fixed address.
- **Proper DNS status handling**: NXDOMAIN, SERVFAIL, and timeouts are
  told apart (via `dnspython`, with a transparent stdlib-`socket`
  fallback if it isn't installed), with configurable retries.
- **Custom resolvers, concurrency limits, and rate limiting** — all
  configurable, so bruteforce/deep enumeration stays bounded and doesn't
  hammer anyone's DNS infrastructure.
- **Runs passive sources concurrently**, not one after another.
- **No `jq` dependency.** crt.sh and theHarvester-JSON parsing are done
  in pure Python.
- **Resilient to flaky upstreams.** crt.sh returns 429/502/503 under
  load; UltraRecon retries with exponential backoff instead of treating
  that as a hard failure.
- **One report, not a dozen text files.** `report.md` / `report.json`
  summarize per-phase timing, per-source counts, wildcards, verified
  hosts, live hosts, and errors in one place.
- **Fails gracefully everywhere.** A missing tool, a bad wordlist, a DNS
  timeout, or an unreachable source never aborts the run — it's logged,
  counted as an error, and the rest of the pipeline continues.
- **Self-updating**: `ultrarecon update` checks GitHub Releases and can
  upgrade itself in place.
- **Offers to install missing tools** it needs, with real install
  commands (not just hints), and a PEP 668 `--break-system-packages`
  fallback.

## Installation

```bash
git clone https://github.com/xtawb/ultrarecon.git
cd ultrarecon
pip install -e .
```

### Requirements

- Python 3.10+
- [`dnspython`](https://www.dnspython.org/) (installed automatically) —
  used for proper NXDOMAIN/SERVFAIL/timeout classification and custom
  resolver support in the bruteforce/deep/resolve stages. If it's ever
  unavailable, UltraRecon transparently falls back to stdlib `socket`
  calls (reduced fidelity, but never a hard failure).

What UltraRecon *orchestrates* are the external recon tools below, each
optional for the passive phase (missing ones are simply skipped):

| Tool | Purpose | Install |
|---|---|---|
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT: hosts, emails, ASNs, IPs | `pip install git+https://github.com/laramies/theHarvester.git` (the PyPI `theHarvester` package is a stale stub — don't use it) |
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

## Basic usage

```bash
# Passive enumeration only (default when no phase flag is given) --
# every available source, DNS resolution, httpx live-probe
ultrarecon scan -d example.com

# Wildcard input is accepted and normalized automatically
ultrarecon scan -d "*.example.com"

# Everything: passive + bruteforce + deep enumeration
ultrarecon scan -d example.com --all
```

## Advanced usage

```bash
# DNS bruteforce with a custom wordlist and higher concurrency
ultrarecon scan -d example.com \
  --bruteforce \
  --wordlist subdomains.txt \
  --concurrency 50

# Deep, recursive wildcard-driven enumeration, bounded to depth 3
ultrarecon scan -d example.com --deep --max-depth 3

# Passive + bruteforce, custom resolvers, rate-limited to 200 qps
ultrarecon scan -d example.com \
  --passive --bruteforce \
  --resolvers 1.1.1.1,8.8.8.8 \
  --rate-limit 200

# Only specific passive sources, skip resolution and the httpx stage
ultrarecon scan -d example.com --only subfinder,amass,crtsh --no-resolve --no-probe

# Custom output directory, ports, and httpx thread count
ultrarecon scan -d example.com -o ./results --ports 80,443,8443 --threads 300

# Auto-confirm any install/update prompts (useful for CI or scripted runs)
ultrarecon scan -d example.com --all --yes
```

## CLI options

```
ultrarecon scan -d DOMAIN [options]

Recon phases:
  --passive               run passive enumeration sources
                           (default when no phase flag is given)
  --bruteforce             run DNS subdomain bruteforce using a wordlist
  --deep                    run recursive wildcard-driven deep enumeration
  --all                     run passive + bruteforce + deep
  --only SRC1,SRC2,...      limit passive sources to this subset
  --no-resolve               skip the DNS resolution/verification stage
  --no-probe                  skip the httpx live-host stage

DNS / bruteforce / deep options:
  --wordlist PATH            wordlist for --bruteforce/--deep
                              (default: built-in list)
  --concurrency N              concurrent DNS queries (default: 50)
  --dns-timeout SEC              per-query DNS timeout (default: 3.0)
  --dns-retries N                  retries on timeout/SERVFAIL (default: 1)
  --resolvers IP,IP,...              custom resolver IPs (needs dnspython)
  --rate-limit QPS                     cap DNS queries/sec (default: unlimited)
  --max-depth N                          max recursion depth (default: 2)

httpx live-probe options:
  --ports PORTS                            (default: 80,443,8080,8000,8888)
  --threads N                                httpx thread count (default: 200)

Misc:
  -o, --outdir PATH        output directory (default: ./out/<domain>)
  -y, --yes                 auto-confirm install/update prompts
  --no-install-prompt        never offer to install missing tools
  --no-update-check           skip the startup update check
  -v, --verbose                 debug-level logging
  -q, --quiet                     only warnings and errors
  --debug                           alias for --verbose
```

Full help for every subcommand: `ultrarecon scan --help`,
`ultrarecon check --help`, `ultrarecon update --help`.

## Bruteforce usage

`--bruteforce` builds `<word>.<domain>` candidates from a wordlist (the
built-in list by default, or `--wordlist path/to/list.txt`), resolves
every one concurrently, and keeps only the ones that actually resolve —
classified by DNS status:

- **OK** → kept as a candidate subdomain.
- **NXDOMAIN** → doesn't exist, discarded.
- **SERVFAIL** / **timeout** → counted as an error, retried up to
  `--dns-retries` times, then discarded (never crashes the run).

Every candidate is also checked against the domain's detected wildcard IP
set (see below) — if it only resolves to the catch-all address, it's
filtered out as DNS noise, not reported as a real subdomain.

```bash
ultrarecon scan -d example.com --bruteforce --wordlist big-list.txt --concurrency 100
```

## Wildcard / deep enumeration

This is the core of what makes UltraRecon different from a flat
bruteforce-and-merge script.

Passive sources sometimes return entries like:

```
*.eaas.arc.io
*.preview\.origin-staging.arc.io
*.testnet.arc.io
account.arc.io
docs.arc.io
```

The `*.` entries are **wildcard patterns**, not literal hostnames — they
mean "some unknown set of hosts exists under this base domain."
`--deep` treats them as enumeration *targets*:

1. Extract the base domain (`*.testnet.arc.io` → `testnet.arc.io`),
   unescaping any presentation-format dots first
   (`*.preview\.origin.arc.io` → `preview.origin.arc.io`).
2. Run wildcard detection on that base — if it itself has a DNS
   catch-all, note the IP(s) so bruteforce results under it can be
   filtered correctly.
3. Bruteforce subdomains under that base with the same wordlist/
   concurrency/timeout/rate-limit settings as `--bruteforce`.
4. If any of the *originally observed* wildcard patterns turn out to be
   a child of a base just processed (e.g. `*.rpc.testnet.arc.io` is a
   child of `testnet.arc.io`), queue it for the next depth level.

Recursion only ever follows wildcard patterns that were **actually
observed** in the enumeration data — never a synthetic guess that every
discovered host might itself be a wildcard base. That keeps it bounded:
combined with `--max-depth` (default 2), it can't run away exponentially
or generate unbounded DNS traffic.

```bash
ultrarecon scan -d example.com --deep --max-depth 3
```

You don't need to re-run passive enumeration to use `--deep` — if
`out/<domain>/1_subdomains.txt` or `wildcards.txt` already exists from a
previous run, UltraRecon reads it automatically and picks up any wildcard
patterns in it. Works with any target, not just a fixed set of domain
names.

## Output structure

```
out/example.com/
├── 0_amass.txt                    # raw per-source passive output
├── 0_subfinder.txt
├── 0_crtsh.txt
├── ...
├── 0_all_candidates.txt           # every raw candidate, pre-resolution
├── theharvester_emails.txt        # OSINT extras from theHarvester
├── theharvester_asns.txt
├── theharvester_ips.txt
├── wildcards.txt                  # wildcard patterns, kept separate
├── 1_subdomains.txt                # unique VERIFIED (resolved) subdomains
├── 2_subdomains_resolved.txt       # kept for backward compatibility
├── 1_subdomains_alive.txt          # live over HTTP/HTTPS (httpx)
├── 1_subdomains_alive_info.txt     # + status code, title, tech stack
├── report.json
└── report.md
```

`1_subdomains.txt` holds **verified** hostnames only (they passed DNS
resolution) — wildcard patterns like `*.testnet.example.com` are never
mixed into it; they live in `wildcards.txt` instead. If you run with
`--no-resolve`, there's no resolution stage to verify against, so
`1_subdomains.txt` falls back to the deduplicated raw candidate list.

## Configuration / performance

Every concurrency-relevant knob is explicit and configurable, on purpose
— speed is never allowed to come at the cost of false positives or
runaway DNS traffic:

| Flag | Controls | Default |
|---|---|---|
| `--concurrency` | parallel DNS queries (bruteforce/deep/resolve) | 50 |
| `--dns-timeout` | per-query timeout (seconds) | 3.0 |
| `--dns-retries` | retries on timeout/SERVFAIL | 1 |
| `--rate-limit` | max DNS queries/sec across all workers | unlimited |
| `--max-depth` | deep-enumeration recursion bound | 2 |
| `--threads` | httpx probe thread count | 200 |
| `--resolvers` | custom nameserver IPs (needs dnspython) | system default |

Passive sources always run concurrently with each other; DNS resolution
(bruteforce, deep, and the final verification pass) is bounded by a
single shared `ThreadPoolExecutor` per phase, so raising `--concurrency`
doesn't multiply out of control across phases.

## Troubleshooting

- **`crt.sh` returns HTTP 502/503/429** — that's crt.sh's own server
  being overloaded (it's a single shared community service), not a bug
  here. UltraRecon retries with exponential backoff automatically; if it
  still fails, the rest of the pipeline continues regardless.
- **`pip install theHarvester` installs something that doesn't work** —
  the PyPI package is a stale, unmaintained stub. Use
  `pip install git+https://github.com/laramies/theHarvester.git`, or let
  `ultrarecon check --install` do it for you.
- **`externally-managed-environment` pip error** — handled automatically;
  UltraRecon retries with `--break-system-packages`.
- **A pip-installed tool "succeeded" but the binary isn't found** — add
  `~/.local/bin` to your `PATH` (a very common gap after `pip install
  --user`) and re-open your shell.
- **`--deep` finds hundreds of bogus subdomains** — this usually means
  the wildcard base has a larger CDN IP rotation pool than the default
  probe count sampled; re-run with more probes isn't currently a flag,
  but you can lower noise with `--rate-limit` and inspect
  `wildcards.txt` to see exactly which bases were flagged.
- **amass/subfinder/assetfinder not found** — `ultrarecon check` shows
  exact install commands; `ultrarecon check --install` (or the in-scan
  prompt) can install them for you where possible.

## Architecture

```
ultrarecon/
├── sources.py       # one adapter class per passive enumeration source
├── patterns.py        # wildcard/escaped-domain parsing & normalization
├── dns_engine.py        # unified DNS queries: NXDOMAIN/SERVFAIL/timeout,
│                           custom resolvers, rate limiting
├── bruteforce.py          # DNS subdomain bruteforce
├── deep.py                  # recursive wildcard-driven deep enumeration
├── resolver.py                # wildcard detection + concurrent resolution
├── probe.py                     # httpx wrapper (alive + tech-detect)
├── installer.py                   # interactive/automatic tool installer
├── updater.py                       # GitHub Releases self-update
├── report.py                          # JSON / Markdown report generation
├── core.py                              # orchestrator: runs every phase,
│                                           merges, classifies, reports
└── cli.py                                 # argparse entry point
                                            (scan / check / update / version)
```

Adding a new passive source means writing one small subclass of `Source`
in `sources.py` and registering it in `ALL_SOURCES` — the orchestrator,
CLI, and report all pick it up automatically.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
ruff check ultrarecon tests
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full release notes. Highlights of
the current release (v1.2.0): DNS bruteforce, recursive wildcard-driven
deep enumeration, escaped-domain parsing, CDN-rotation-aware wildcard
detection, a rebuilt DNS engine (NXDOMAIN/SERVFAIL/timeout, custom
resolvers, rate limiting), phase-based CLI (`--passive/--bruteforce/
--deep/--all`), and phase-timed reports.

## Legal

This tool automates **passive, semi-passive, and low-and-slow active**
reconnaissance (DNS bruteforce and resolution) — it does not exploit
anything or attempt to bypass access controls, authentication, or WAF
protections. Even so, you are responsible for only pointing it at domains
you are authorized to test: an in-scope bug bounty / VDP target, or
infrastructure you own. Scanning domains without authorization may
violate computer-crime laws in your jurisdiction. All concurrency and
rate limits are configurable specifically so you can keep DNS traffic
bounded and considerate. The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
