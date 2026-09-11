from pathlib import Path

from ultrarecon.utils import is_valid_domain, normalize_domain, read_lines, write_lines


def test_normalize_domain_strips_scheme_and_wildcard():
    assert normalize_domain("*.example.com") == "example.com"
    assert normalize_domain("https://example.com/") == "example.com"
    assert normalize_domain("HTTP://Example.COM:8080/path") == "example.com"


def test_is_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.co.uk")
    assert not is_valid_domain("-bad.com")
    assert not is_valid_domain("not a domain")


def test_write_and_read_lines_roundtrip(tmp_path: Path):
    target = tmp_path / "hosts.txt"
    write_lines(target, {"b.example.com", "a.example.com"})
    assert read_lines(target) == {"a.example.com", "b.example.com"}


def test_write_lines_empty(tmp_path: Path):
    target = tmp_path / "empty.txt"
    write_lines(target, set())
    assert read_lines(target) == set()
