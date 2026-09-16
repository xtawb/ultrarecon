"""Parsing helpers for wildcard and escaped-domain entries.

Some sources (amass in particular) emit raw zone-file style entries like:

    *.eaas.arc.io
    *.preview\\.origin-staging.arc.io

The first is a genuine wildcard pattern: "any hostname under eaas.arc.io".
The second is an escaped dot inside a label — the `\\.` is DNS
presentation-format escaping, not a literal backslash-dot in the hostname.
For resolution and enumeration purposes it should be treated exactly like
`preview.origin-staging.arc.io`.

This module is the single place that understands both cases, so every
other stage (bruteforce, deep enumeration, output classification) agrees
on what counts as a wildcard and what a normalized hostname looks like.
"""
from __future__ import annotations

WILDCARD_PREFIX = "*."


def unescape_domain(raw: str) -> str:
    """Turn escaped presentation-format dots into literal dots.

    'preview\\.origin-staging.arc.io' -> 'preview.origin-staging.arc.io'
    """
    return raw.replace("\\.", ".")


def is_wildcard_entry(raw: str) -> bool:
    return raw.strip().startswith(WILDCARD_PREFIX)


def normalize_entry(raw: str) -> str:
    """Normalize any raw source line: strip, unescape, lowercase."""
    return unescape_domain(raw.strip()).lower()


def wildcard_base(raw: str) -> str | None:
    """Return the base domain behind a wildcard pattern, or None otherwise.

    '*.eaas.arc.io'                    -> 'eaas.arc.io'
    '*.preview\\.origin.arc.io'         -> 'preview.origin.arc.io'
    'account.arc.io'                   -> None (not a wildcard)
    """
    entry = normalize_entry(raw)
    if not entry.startswith(WILDCARD_PREFIX):
        return None
    base = entry[len(WILDCARD_PREFIX):]
    return base or None


def classify_entries(entries: set[str]) -> tuple[set[str], set[str]]:
    """Split raw entries into (verified_hostname_candidates, wildcard_patterns).

    Every entry is normalized (unescaped + lowercased) along the way, so
    downstream code never has to think about escaping again.
    """
    hostnames: set[str] = set()
    wildcards: set[str] = set()
    for raw in entries:
        entry = normalize_entry(raw)
        if not entry:
            continue
        if entry.startswith(WILDCARD_PREFIX):
            wildcards.add(entry)
        else:
            hostnames.add(entry)
    return hostnames, wildcards
