from unittest.mock import patch

from ultrarecon.resolver import detect_wildcard, resolve_all


def test_detect_wildcard_positive():
    with patch("ultrarecon.resolver._resolve", return_value="1.2.3.4"):
        assert detect_wildcard("example.com") == "1.2.3.4"


def test_detect_wildcard_negative():
    with patch("ultrarecon.resolver._resolve", return_value=None):
        assert detect_wildcard("example.com") is None


def test_resolve_all_filters_unresolvable():
    def fake_resolve(host):
        return "9.9.9.9" if host == "good.example.com" else None

    with patch("ultrarecon.resolver._resolve", side_effect=fake_resolve):
        result = resolve_all({"good.example.com", "bad.example.com"})
    assert result == {"good.example.com": "9.9.9.9"}
