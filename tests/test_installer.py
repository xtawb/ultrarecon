from unittest.mock import patch

from ultrarecon.installer import build_command


def test_build_command_known_tool():
    assert "pip install" in build_command("theharvester")
    assert "go install" in build_command("subfinder")


def test_amass_prefers_snap_when_available():
    with patch("ultrarecon.installer.which", side_effect=lambda b: b == "snap"):
        assert build_command("amass") == "sudo snap install amass"


def test_amass_falls_back_to_go():
    with patch("ultrarecon.installer.which", side_effect=lambda b: b == "go"):
        assert "go install" in build_command("amass")


def test_amass_no_manager_available():
    with patch("ultrarecon.installer.which", return_value=False):
        assert build_command("amass") is None


def test_unknown_tool_returns_none():
    assert build_command("not-a-real-tool") is None
