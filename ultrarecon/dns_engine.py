"""Single place all DNS queries go through.

Every other module (bruteforce, wildcard detection, deep enumeration,
resolution filtering) calls into here so they all get the same NXDOMAIN /
SERVFAIL / timeout handling and the same optional custom-resolver support,
instead of each re-implementing socket calls slightly differently.

dnspython is used when available, because it's the only way to reliably
tell NXDOMAIN apart from SERVFAIL apart from a timeout, and the only way
to query specific resolvers instead of the system default. If dnspython
isn't installed, everything still works through stdlib `socket` — with
reduced fidelity (no custom resolvers, and failures are reported generically)
rather than failing outright.
"""
from __future__ import annotations

import random
import socket
import string
import threading
import time
from dataclasses import dataclass
from enum import Enum

try:
    import dns.exception
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - exercised via monkeypatched tests
    HAS_DNSPYTHON = False


class DnsStatus(str, Enum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class DnsResult:
    host: str
    status: DnsStatus
    ip: str | None = None


class RateLimiter:
    """Enforces a maximum average rate across however many worker threads
    are calling it, by spacing out a shared 'next allowed time' cursor."""

    def __init__(self, rate_per_sec: float | None):
        self.interval = (1.0 / rate_per_sec) if rate_per_sec else 0.0
        self._lock = threading.Lock()
        self._next_time = time.monotonic()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(self._next_time, now)
            self._next_time = start + self.interval
            delay = start - now
        if delay > 0:
            time.sleep(delay)


def make_resolver(resolvers: list[str] | None, timeout: float):
    """Build a dnspython Resolver, or return None to fall back to socket."""
    if not HAS_DNSPYTHON:
        return None
    r = dns.resolver.Resolver()
    if resolvers:
        r.nameservers = resolvers
    r.timeout = timeout
    r.lifetime = timeout
    return r


def query(host: str, resolver=None, timeout: float = 3.0, retries: int = 1) -> DnsResult:
    """Resolve one hostname's A record with proper status classification."""
    if HAS_DNSPYTHON and resolver is not None:
        return _query_dnspython(host, resolver, retries)
    return _query_socket(host)


def _query_dnspython(host: str, resolver, retries: int) -> DnsResult:
    attempts = max(1, retries + 1)
    saw_timeout = False
    for _ in range(attempts):
        try:
            answer = resolver.resolve(host, "A")
            return DnsResult(host, DnsStatus.OK, str(answer[0]))
        except dns.resolver.NXDOMAIN:
            return DnsResult(host, DnsStatus.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DnsResult(host, DnsStatus.NXDOMAIN)
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            saw_timeout = True
            continue
        except dns.resolver.NoNameservers:
            # every configured nameserver refused/failed -> SERVFAIL-class
            continue
        except dns.exception.DNSException:
            continue
    return DnsResult(host, DnsStatus.TIMEOUT if saw_timeout else DnsStatus.SERVFAIL)


def _query_socket(host: str) -> DnsResult:
    """Fallback path with no dnspython: coarser, but never crashes the run."""
    try:
        ip = socket.gethostbyname(host)
        return DnsResult(host, DnsStatus.OK, ip)
    except socket.gaierror:
        return DnsResult(host, DnsStatus.NXDOMAIN)
    except TimeoutError:
        return DnsResult(host, DnsStatus.TIMEOUT)
    except (OSError, UnicodeError):
        return DnsResult(host, DnsStatus.ERROR)


def random_label(length: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
