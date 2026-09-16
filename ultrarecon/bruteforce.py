"""DNS subdomain bruteforce.

Takes a wordlist, builds `<word>.<domain>` candidates, and resolves every
one of them concurrently through `dns_engine` — so it gets the same
NXDOMAIN/SERVFAIL/timeout classification, retry behavior, custom-resolver
support, and rate limiting as everything else in the DNS pipeline.

A candidate only counts as a found subdomain if it actually resolves
(status OK) AND, when a wildcard IP is known for the parent domain, its
answer isn't just that catch-all IP. Nothing here treats "resolves" as
proof of anything more than "resolves."
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from . import dns_engine
from .dns_engine import DnsStatus

DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "default.txt"


class WordlistError(Exception):
    pass


def load_wordlist(path: str | Path | None) -> list[str]:
    p = Path(path) if path else DEFAULT_WORDLIST
    if not p.exists():
        raise WordlistError(f"wordlist not found: {p}")
    words = []
    seen = set()
    for line in p.read_text(errors="ignore").splitlines():
        w = line.strip().lower()
        if not w or w.startswith("#") or w in seen:
            continue
        seen.add(w)
        words.append(w)
    if not words:
        raise WordlistError(f"wordlist is empty: {p}")
    return words


@dataclass
class BruteforceStats:
    total: int = 0
    ok: int = 0
    nxdomain: int = 0
    servfail: int = 0
    timeout: int = 0
    error: int = 0
    filtered_wildcard: int = 0

    def record(self, status: DnsStatus) -> None:
        self.total += 1
        setattr(self, status.value, getattr(self, status.value) + 1)


@dataclass
class BruteforceResult:
    found: set[str] = field(default_factory=set)
    stats: BruteforceStats = field(default_factory=BruteforceStats)


def bruteforce(
    domain: str,
    wordlist: list[str],
    *,
    concurrency: int = 50,
    timeout: float = 3.0,
    retries: int = 1,
    resolvers: list[str] | None = None,
    rate_limit: float | None = None,
    wildcard_ip: str | set[str] | None = None,
) -> BruteforceResult:
    resolver = dns_engine.make_resolver(resolvers, timeout)
    limiter = dns_engine.RateLimiter(rate_limit)
    result = BruteforceResult()
    candidates = {f"{word}.{domain}" for word in wordlist}
    wildcard_ips: set[str] = (
        wildcard_ip if isinstance(wildcard_ip, set) else ({wildcard_ip} if wildcard_ip else set())
    )

    def task(host: str):
        limiter.wait()
        return dns_engine.query(host, resolver=resolver, timeout=timeout, retries=retries)

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(task, h): h for h in candidates}
        for fut in as_completed(futures):
            r = fut.result()
            result.stats.record(r.status)
            if r.status != DnsStatus.OK:
                continue
            if r.ip in wildcard_ips:
                result.stats.filtered_wildcard += 1
                continue
            result.found.add(r.host)

    return result
