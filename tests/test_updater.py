from unittest.mock import patch

from ultrarecon.updater import _parse_version, check_for_update


def test_parse_version_basic():
    assert _parse_version("1.2.3") == (1, 2, 3)
    assert _parse_version("v1.2.3") == (1, 2, 3)


def test_parse_version_ordering():
    assert _parse_version("1.10.0") > _parse_version("1.9.9")
    assert _parse_version("2.0.0") > _parse_version("1.99.99")


def test_check_for_update_detects_newer():
    with patch("ultrarecon.updater.fetch_latest_release", return_value={"tag_name": "v99.0.0"}):
        available, tag = check_for_update()
    assert available is True
    assert tag == "v99.0.0"


def test_check_for_update_no_release():
    with patch("ultrarecon.updater.fetch_latest_release", return_value=None):
        available, tag = check_for_update()
    assert available is False
    assert tag is None


def test_check_for_update_same_version():
    from ultrarecon import __version__
    with patch("ultrarecon.updater.fetch_latest_release", return_value={"tag_name": __version__}):
        available, _ = check_for_update()
    assert available is False
