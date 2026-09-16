from unittest.mock import MagicMock, patch

from ultrarecon.updater import _parse_version, check_for_update, self_update


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


def test_self_update_success_on_first_try():
    ok_proc = MagicMock(returncode=0, stdout="Successfully installed ultrarecon-1.2.0\n", stderr="")
    with patch("ultrarecon.updater.subprocess.run", return_value=ok_proc) as mock_run:
        ok, message = self_update()
    assert ok is True
    assert "Successfully installed" in message
    assert mock_run.call_count == 1


def test_self_update_retries_with_break_system_packages():
    """Mirrors the real-world failure a Kali/Debian PEP 668 environment hits."""
    managed_error = MagicMock(
        returncode=1,
        stdout="",
        stderr="error: externally-managed-environment\n\n\u00d7 This environment is externally managed",
    )
    ok_proc = MagicMock(returncode=0, stdout="Successfully installed ultrarecon-1.2.0\n", stderr="")

    with patch("ultrarecon.updater.subprocess.run", side_effect=[managed_error, ok_proc]) as mock_run:
        ok, message = self_update()

    assert ok is True
    assert "--break-system-packages" in message
    assert mock_run.call_count == 2
    second_call_cmd = mock_run.call_args_list[1].args[0]
    assert "--break-system-packages" in second_call_cmd


def test_self_update_fails_cleanly_when_both_attempts_fail():
    managed_error = MagicMock(returncode=1, stdout="", stderr="error: externally-managed-environment")
    still_fails = MagicMock(returncode=1, stdout="", stderr="permission denied")

    with patch("ultrarecon.updater.subprocess.run", side_effect=[managed_error, still_fails]):
        ok, message = self_update()

    assert ok is False
    assert "permission denied" in message


def test_self_update_does_not_retry_on_unrelated_failure():
    other_error = MagicMock(returncode=1, stdout="", stderr="could not find a version that satisfies")
    with patch("ultrarecon.updater.subprocess.run", return_value=other_error) as mock_run:
        ok, _message = self_update()
    assert ok is False
    assert mock_run.call_count == 1
