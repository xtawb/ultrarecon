import argparse

import pytest

from ultrarecon.cli import _parse_resolvers, _resolve_phases, build_parser


def _ns(**overrides):
    base = {"passive": False, "bruteforce": False, "deep": False, "all": False}
    base.update(overrides)
    return argparse.Namespace(**base)


def test_resolve_phases_default_is_passive_only():
    assert _resolve_phases(_ns()) == (True, False, False)


def test_resolve_phases_all_flag():
    assert _resolve_phases(_ns(all=True)) == (True, True, True)


def test_resolve_phases_explicit_bruteforce_only():
    assert _resolve_phases(_ns(bruteforce=True)) == (False, True, False)


def test_resolve_phases_explicit_deep_only():
    assert _resolve_phases(_ns(deep=True)) == (False, False, True)


def test_resolve_phases_passive_and_bruteforce_combo():
    assert _resolve_phases(_ns(passive=True, bruteforce=True)) == (True, True, False)


def test_parse_resolvers_none():
    assert _parse_resolvers(None) is None
    assert _parse_resolvers("") is None


def test_parse_resolvers_splits_and_strips():
    assert _parse_resolvers("8.8.8.8, 1.1.1.1 ,9.9.9.9") == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def test_cli_help_does_not_crash(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0


def test_scan_help_lists_new_flags(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--help"])
    out = capsys.readouterr().out
    for flag in ("--passive", "--bruteforce", "--deep", "--all", "--wordlist",
                 "--concurrency", "--max-depth", "--resolvers", "--rate-limit"):
        assert flag in out


def test_scan_requires_domain():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan"])


def test_scan_parses_new_options():
    parser = build_parser()
    args = parser.parse_args([
        "scan", "-d", "example.com", "--bruteforce", "--deep",
        "--wordlist", "words.txt", "--concurrency", "10",
        "--max-depth", "1", "--resolvers", "8.8.8.8,1.1.1.1",
        "--rate-limit", "5", "--dns-timeout", "2.5", "--dns-retries", "2",
    ])
    assert args.bruteforce and args.deep
    assert args.wordlist == "words.txt"
    assert args.concurrency == 10
    assert args.max_depth == 1
    assert args.resolvers == "8.8.8.8,1.1.1.1"
    assert args.rate_limit == 5
    assert args.dns_timeout == 2.5
    assert args.dns_retries == 2


def test_wordlists_list_parses():
    parser = build_parser()
    args = parser.parse_args(["wordlists", "list"])
    assert args.command == "wordlists"
    assert args.wordlists_command == "list"


def test_wordlists_get_parses():
    parser = build_parser()
    args = parser.parse_args(["wordlists", "get", "seclists-5k"])
    assert args.wordlists_command == "get"
    assert args.name == "seclists-5k"
    assert args.force is False


def test_wordlists_get_force_flag():
    parser = build_parser()
    args = parser.parse_args(["wordlists", "get", "seclists-5k", "--force"])
    assert args.force is True


def test_wordlists_requires_subcommand():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["wordlists"])


def test_scan_wordlist_accepts_registry_name_or_url():
    parser = build_parser()
    args = parser.parse_args(["scan", "-d", "example.com", "--bruteforce", "--wordlist", "seclists-5k"])
    assert args.wordlist == "seclists-5k"
    args2 = parser.parse_args([
        "scan", "-d", "example.com", "--bruteforce",
        "--wordlist", "https://raw.githubusercontent.com/x/y/main/list.txt",
    ])
    assert args2.wordlist.startswith("https://")
