from unittest.mock import patch

import pytest

from ultrarecon import bruteforce as bf
from ultrarecon.dns_engine import DnsResult, DnsStatus


def test_load_wordlist_missing_file(tmp_path):
    with pytest.raises(bf.WordlistError):
        bf.load_wordlist(tmp_path / "does-not-exist.txt")


def test_load_wordlist_empty_file(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_text("# just comments\n\n")
    with pytest.raises(bf.WordlistError):
        bf.load_wordlist(p)


def test_load_wordlist_dedupes_and_strips(tmp_path):
    p = tmp_path / "words.txt"
    p.write_text("www\nWWW\n# comment\n\napi\napi\n")
    words = bf.load_wordlist(p)
    assert words == ["www", "api"]


def test_load_wordlist_default_exists():
    words = bf.load_wordlist(None)
    assert len(words) > 10
    assert "www" in words


def test_bruteforce_finds_resolvable_hosts():
    def fake_query(host, resolver=None, timeout=3.0, retries=1):
        if host.startswith("api."):
            return DnsResult(host, DnsStatus.OK, "1.1.1.1")
        return DnsResult(host, DnsStatus.NXDOMAIN)

    with patch("ultrarecon.bruteforce.dns_engine.query", side_effect=fake_query):
        result = bf.bruteforce("example.com", ["api", "dev", "www"], concurrency=5)

    assert result.found == {"api.example.com"}
    assert result.stats.total == 3
    assert result.stats.ok == 1
    assert result.stats.nxdomain == 2


def test_bruteforce_filters_wildcard_noise():
    def fake_query(host, resolver=None, timeout=3.0, retries=1):
        return DnsResult(host, DnsStatus.OK, "9.9.9.9")

    with patch("ultrarecon.bruteforce.dns_engine.query", side_effect=fake_query):
        result = bf.bruteforce(
            "example.com", ["a", "b", "c"], concurrency=5, wildcard_ip="9.9.9.9"
        )

    assert result.found == set()
    assert result.stats.filtered_wildcard == 3


def test_bruteforce_empty_wordlist_returns_empty_result():
    result = bf.bruteforce("example.com", [], concurrency=5)
    assert result.found == set()
    assert result.stats.total == 0
