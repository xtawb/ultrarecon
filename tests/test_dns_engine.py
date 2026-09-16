import time
from unittest.mock import MagicMock, patch

import pytest

from ultrarecon import dns_engine
from ultrarecon.dns_engine import DnsStatus, RateLimiter, _query_socket


def test_query_socket_ok():
    with patch("socket.gethostbyname", return_value="1.2.3.4"):
        result = _query_socket("example.com")
    assert result.status == DnsStatus.OK
    assert result.ip == "1.2.3.4"


def test_query_socket_nxdomain():
    import socket as socket_mod

    with patch("socket.gethostbyname", side_effect=socket_mod.gaierror):
        result = _query_socket("doesnotexist.example.com")
    assert result.status == DnsStatus.NXDOMAIN


def test_query_socket_timeout():
    with patch("socket.gethostbyname", side_effect=TimeoutError):
        result = _query_socket("slow.example.com")
    assert result.status == DnsStatus.TIMEOUT


def test_query_dnspython_nxdomain(monkeypatch):
    if not dns_engine.HAS_DNSPYTHON:
        pytest.skip("dnspython not installed")
    import dns.resolver as real_dns_resolver

    fake_resolver = MagicMock()
    fake_resolver.resolve.side_effect = real_dns_resolver.NXDOMAIN()
    result = dns_engine.query("nope.example.com", resolver=fake_resolver, retries=0)
    assert result.status == DnsStatus.NXDOMAIN


def test_query_dnspython_ok(monkeypatch):
    if not dns_engine.HAS_DNSPYTHON:
        pytest.skip("dnspython not installed")
    fake_answer = [MagicMock(__str__=lambda self: "5.6.7.8")]
    fake_resolver = MagicMock()
    fake_resolver.resolve.return_value = fake_answer
    result = dns_engine.query("ok.example.com", resolver=fake_resolver, retries=0)
    assert result.status == DnsStatus.OK
    assert result.ip == "5.6.7.8"


def test_rate_limiter_spaces_out_calls():
    limiter = RateLimiter(rate_per_sec=20)  # 1 call per 0.05s
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.09  # roughly 2 intervals of ~0.05s


def test_rate_limiter_disabled_when_none():
    limiter = RateLimiter(rate_per_sec=None)
    start = time.monotonic()
    for _ in range(50):
        limiter.wait()
    assert time.monotonic() - start < 0.05


def test_random_label_length_and_charset():
    label = dns_engine.random_label(12)
    assert len(label) == 12
    assert label.isalnum()
    assert label == label.lower()
