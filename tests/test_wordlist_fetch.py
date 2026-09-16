from unittest.mock import patch

import pytest

from ultrarecon import wordlist_fetch as wf


def test_registry_has_expected_entries():
    names = set(wf.REGISTRY.keys())
    assert "seclists-5k" in names
    assert "n0kovo-huge" in names
    for src in wf.REGISTRY.values():
        assert src.url.startswith("https://raw.githubusercontent.com/")
        assert src.lines > 0


def test_get_unknown_name_raises():
    with pytest.raises(wf.WordlistFetchError):
        wf.get("not-a-real-wordlist")


def test_resolve_none_passthrough():
    assert wf.resolve(None) is None


def test_resolve_local_path_passthrough(tmp_path):
    local = tmp_path / "mywords.txt"
    local.write_text("www\napi\n")
    assert wf.resolve(str(local)) == str(local)


def test_resolve_registry_name_downloads(tmp_path):
    with patch.object(wf, "CACHE_DIR", tmp_path), \
         patch.object(wf, "_download") as mock_download:
        def fake_download(url, dest, logger=None, timeout=30.0):
            dest.write_text("www\napi\ndev\n")
        mock_download.side_effect = fake_download

        result = wf.resolve("seclists-5k")

    assert result == str(tmp_path / "seclists-5k.txt")
    assert (tmp_path / "seclists-5k.txt").read_text() == "www\napi\ndev\n"
    mock_download.assert_called_once()


def test_get_uses_cache_without_redownloading(tmp_path):
    cached = tmp_path / "seclists-5k.txt"
    cached.write_text("cached-content")
    with patch.object(wf, "CACHE_DIR", tmp_path), patch.object(wf, "_download") as mock_download:
        result = wf.get("seclists-5k")
    assert result == cached
    mock_download.assert_not_called()


def test_get_force_redownloads_even_if_cached(tmp_path):
    cached = tmp_path / "seclists-5k.txt"
    cached.write_text("stale-content")
    with patch.object(wf, "CACHE_DIR", tmp_path), patch.object(wf, "_download") as mock_download:
        wf.get("seclists-5k", force=True)
    mock_download.assert_called_once()


def test_resolve_url_downloads_and_caches(tmp_path):
    url = "https://raw.githubusercontent.com/someone/somelist/main/list.txt"
    with patch.object(wf, "CACHE_DIR", tmp_path), \
         patch.object(wf, "_download") as mock_download:
        def fake_download(u, dest, logger=None, timeout=30.0):
            dest.write_text("custom\nwords\n")
        mock_download.side_effect = fake_download

        result = wf.resolve(url)

    assert result is not None
    assert "url_" in result
    mock_download.assert_called_once()


def test_list_registry_reports_cache_status(tmp_path):
    with patch.object(wf, "CACHE_DIR", tmp_path):
        (tmp_path / "seclists-5k.txt").write_text("x")
        results = wf.list_registry()
    status = {src.name: cached for src, cached in results}
    assert status["seclists-5k"] is True
    assert status["n0kovo-huge"] is False
