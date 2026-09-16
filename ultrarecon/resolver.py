"""DNS sanity layer -- wildcard detection + concurrent resolution.

This module's public API (`detect_wildcard`, `resolve_all`) is unchanged
from earlier versions so nothing importing it needs to change. Internally
it now goes through `dns_engine`, which means it automatically gets proper
NXDOMAIN/SERVFAIL/timeout handling and optional custom-resolver support
when dnspython is installed, with a transparent fallback to stdlib socket
calls when it isn't.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from . import dns_engine
from .dns_engine import DnsStatus


def detect_wildcard(
    domain: str,
    probes: int = 8,
    resolvers: list[str] | None = None,
    timeout: float = 3.0,
) -> set[str] | None:
    """Return the set of wildcard/catch-all IPs for `domain`, or None.

    CDN-fronted wildcards (Cloudflare, Fastly, CloudFront, ...) commonly
    rotate between several IPs rather than returning one fixed address, so
    this doesn't require every probe to match exactly -- it requires every
    independent random, non-existent label to resolve at all. If they all
    do, the domain has a catch-all, and every IP seen across the probes is
    treated as wildcard noise for filtering purposes. A larger probe count
    catches larger rotation pools more reliably, at the cost of a few
    extra queries; for very large CDN IP pools a small residue of false
    positives can still slip through -- this is a best-effort filter, not
    a guarantee.
    """
    resolver = dns_engine.make_resolver(resolvers, timeout)
    answers: set[str] = set()
    for _ in range(probes):
        junk_host = f"{dns_engine.random_label()}.{domain}"
        result = dns_engine.query(junk_host, resolver=resolver, timeout=timeout)
        if result.status != DnsStatus.OK:
            return None
        answers.add(result.ip)
    return answers or None


def resolve_all(
    hosts: set[str],
    workers: int = 100,
    resolvers: list[str] | None = None,
    timeout: float = 3.0,
    retries: int = 1,
    rate_limit: float | None = None,
) -> dict[str, str]:
    """Resolve every host concurrently. Returns {host: ip} for those that resolve."""
    resolver = dns_engine.make_resolver(resolvers, timeout)
    limiter = dns_engine.RateLimiter(rate_limit)
    resolved: dict[str, str] = {}

    def task(host: str):
        limiter.wait()
        return dns_engine.query(host, resolver=resolver, timeout=timeout, retries=retries)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(task, h): h for h in hosts}
        for fut in as_completed(futures):
            result = fut.result()
            if result.status == DnsStatus.OK:
                resolved[result.host] = result.ip
    return resolved
