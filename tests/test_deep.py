from unittest.mock import patch

from ultrarecon import deep as deep_mod
from ultrarecon.bruteforce import BruteforceResult, BruteforceStats


def _fake_bruteforce_factory(mapping):
    """Return a fake `bruteforce()` that yields mapping[base] found hosts."""

    def fake(base, wordlist, **kwargs):
        found = mapping.get(base, set())
        return BruteforceResult(found=set(found), stats=BruteforceStats(total=len(wordlist)))

    return fake


def test_deep_enumerate_single_level():
    wildcards = {"*.testnet.example.com"}
    mapping = {"testnet.example.com": {"rpc.testnet.example.com", "api.testnet.example.com"}}

    with patch("ultrarecon.deep.bf.bruteforce", side_effect=_fake_bruteforce_factory(mapping)), \
         patch("ultrarecon.deep.wildcard_resolver.detect_wildcard", return_value=None):
        result = deep_mod.deep_enumerate(wildcards, ["rpc", "api"], max_depth=2)

    assert result.discovered == {"rpc.testnet.example.com", "api.testnet.example.com"}
    assert result.visited_bases == {"testnet.example.com"}
    assert result.depth_reached == 1


def test_deep_enumerate_recurses_into_observed_wildcard():
    wildcards = {"*.testnet.example.com", "*.rpc.testnet.example.com"}
    mapping = {
        "testnet.example.com": {"rpc.testnet.example.com"},
        "rpc.testnet.example.com": {"east.rpc.testnet.example.com"},
    }

    with patch("ultrarecon.deep.bf.bruteforce", side_effect=_fake_bruteforce_factory(mapping)), \
         patch("ultrarecon.deep.wildcard_resolver.detect_wildcard", return_value=None):
        result = deep_mod.deep_enumerate(wildcards, ["rpc", "east"], max_depth=3)

    assert "east.rpc.testnet.example.com" in result.discovered
    assert result.visited_bases == {"testnet.example.com", "rpc.testnet.example.com"}
    assert result.depth_reached == 2


def test_deep_enumerate_respects_max_depth():
    wildcards = {"*.testnet.example.com", "*.rpc.testnet.example.com"}
    mapping = {
        "testnet.example.com": {"rpc.testnet.example.com"},
        "rpc.testnet.example.com": {"east.rpc.testnet.example.com"},
    }

    with patch("ultrarecon.deep.bf.bruteforce", side_effect=_fake_bruteforce_factory(mapping)), \
         patch("ultrarecon.deep.wildcard_resolver.detect_wildcard", return_value=None):
        result = deep_mod.deep_enumerate(wildcards, ["rpc", "east"], max_depth=1)

    # Only the first level should have been visited with max_depth=1
    assert result.visited_bases == {"testnet.example.com"}
    assert "east.rpc.testnet.example.com" not in result.discovered


def test_deep_enumerate_no_wildcards_returns_empty():
    result = deep_mod.deep_enumerate(set(), ["rpc"], max_depth=2)
    assert result.discovered == set()
    assert result.visited_bases == set()


def test_deep_enumerate_max_depth_zero_noop():
    with patch("ultrarecon.deep.bf.bruteforce") as mock_bf:
        result = deep_mod.deep_enumerate({"*.testnet.example.com"}, ["rpc"], max_depth=0)
    mock_bf.assert_not_called()
    assert result.discovered == set()


def test_deep_enumerate_never_revisits_same_base():
    """Two wildcard patterns with the same base must only be bruteforced once."""
    wildcards = {"*.testnet.example.com"}
    call_count = {"n": 0}

    def counting_fake(base, wordlist, **kwargs):
        call_count["n"] += 1
        return BruteforceResult(found=set(), stats=BruteforceStats(total=len(wordlist)))

    with patch("ultrarecon.deep.bf.bruteforce", side_effect=counting_fake), \
         patch("ultrarecon.deep.wildcard_resolver.detect_wildcard", return_value=None):
        deep_mod.deep_enumerate(wildcards, ["rpc"], max_depth=2)

    assert call_count["n"] == 1
