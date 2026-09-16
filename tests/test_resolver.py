from unittest.mock import patch

from ultrarecon.dns_engine import DnsResult, DnsStatus
from ultrarecon.resolver import detect_wildcard, resolve_all


def test_detect_wildcard_single_consistent_ip():
    with patch(
        "ultrarecon.resolver.dns_engine.query",
        return_value=DnsResult("junk.example.com", DnsStatus.OK, "1.2.3.4"),
    ):
        assert detect_wildcard("example.com") == {"1.2.3.4"}


def test_detect_wildcard_negative():
    with patch(
        "ultrarecon.resolver.dns_engine.query",
        return_value=DnsResult("junk.example.com", DnsStatus.NXDOMAIN),
    ):
        assert detect_wildcard("example.com") is None


def test_detect_wildcard_rotating_cdn_ips():
    """CDN-fronted wildcards (Cloudflare etc.) rotate between several IPs --
    every probe must still resolve, but the exact IP doesn't need to match."""
    ips = iter(["104.18.20.97", "104.18.21.97", "104.18.20.97", "104.18.21.97"])

    def fake_query(host, resolver=None, timeout=3.0):
        return DnsResult(host, DnsStatus.OK, next(ips))

    with patch("ultrarecon.resolver.dns_engine.query", side_effect=fake_query):
        result = detect_wildcard("example.com", probes=4)
    assert result == {"104.18.20.97", "104.18.21.97"}


def test_resolve_all_filters_unresolvable():
    def fake_query(host, resolver=None, timeout=3.0, retries=1):
        if host == "good.example.com":
            return DnsResult(host, DnsStatus.OK, "9.9.9.9")
        return DnsResult(host, DnsStatus.NXDOMAIN)

    with patch("ultrarecon.resolver.dns_engine.query", side_effect=fake_query):
        result = resolve_all({"good.example.com", "bad.example.com"})
    assert result == {"good.example.com": "9.9.9.9"}
