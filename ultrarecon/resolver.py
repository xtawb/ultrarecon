"""DNS sanity layer.

Two things most quick recon scripts skip, but that matter a lot in
practice:

1. Wildcard DNS detection — some targets resolve *any* subdomain to the
   same IP (a catch-all record). Without detecting this, every enumerated
   name looks "alive," which floods the results with noise.
2. Concurrent resolution — filtering out names that don't resolve at all
   before handing the list to httpx saves time and avoids false negatives
   caused by httpx's own timeouts under heavy load.
"""
from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except (TimeoutError, socket.gaierror, UnicodeError):
        return None


def detect_wildcard(domain: str, probes: int = 3) -> str | None:
    """Return the wildcard IP if the domain has a catch-all DNS record."""
    answers = set()
    for _ in range(probes):
        junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        ip = _resolve(f"{junk}.{domain}")
        if ip is None:
            return None
        answers.add(ip)
    # If every random, non-existent probe resolves to the same IP, it's a wildcard.
    return answers.pop() if len(answers) == 1 else None


def resolve_all(hosts: set[str], workers: int = 100) -> dict[str, str]:
    """Resolve every host concurrently. Returns {host: ip} for those that resolve."""
    resolved: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve, h): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            ip = fut.result()
            if ip:
                resolved[host] = ip
    return resolved
