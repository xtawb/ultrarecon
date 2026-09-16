from ultrarecon.patterns import (
    classify_entries,
    is_wildcard_entry,
    normalize_entry,
    unescape_domain,
    wildcard_base,
)


def test_unescape_domain():
    assert unescape_domain("preview\\.origin-staging.arc.io") == "preview.origin-staging.arc.io"
    assert unescape_domain("plain.example.com") == "plain.example.com"


def test_is_wildcard_entry():
    assert is_wildcard_entry("*.eaas.arc.io")
    assert not is_wildcard_entry("account.arc.io")
    assert not is_wildcard_entry("")


def test_wildcard_base_plain():
    assert wildcard_base("*.eaas.arc.io") == "eaas.arc.io"


def test_wildcard_base_escaped():
    assert wildcard_base("*.preview\\.origin-staging.arc.io") == "preview.origin-staging.arc.io"


def test_wildcard_base_non_wildcard_returns_none():
    assert wildcard_base("account.arc.io") is None


def test_normalize_entry_lowercases_and_unescapes():
    assert normalize_entry("  ACCOUNT\\.Test.ARC.IO  ") == "account.test.arc.io"


def test_classify_entries_splits_correctly():
    entries = {
        "*.eaas.arc.io",
        "*.preview\\.origin-staging.arc.io",
        "account.arc.io",
        "docs.arc.io",
        "",
        "   ",
    }
    hostnames, wildcards = classify_entries(entries)
    assert hostnames == {"account.arc.io", "docs.arc.io"}
    assert wildcards == {"*.eaas.arc.io", "*.preview.origin-staging.arc.io"}


def test_classify_entries_empty_set():
    hostnames, wildcards = classify_entries(set())
    assert hostnames == set()
    assert wildcards == set()
