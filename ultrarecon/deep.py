"""Deep, wildcard-driven subdomain enumeration.

The idea (see README "Wildcard / deep enumeration"): a wildcard pattern
like `*.testnet.arc.io` isn't just a line to store — it's an instruction
to go look for real hostnames under `testnet.arc.io`. If that search turns
up something that itself has a wildcard pattern among the data already
collected (e.g. `*.rpc.testnet.arc.io`), the same process repeats one
level deeper, bounded by `max_depth`.

Recursion only ever follows wildcard patterns that were actually observed
in the enumeration data — never a synthetic guess that every discovered
host might itself be a wildcard base. That keeps this bounded and avoids
the "uncontrolled concurrency / resource exhaustion" failure mode a naive
"recurse into everything" implementation would have.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import bruteforce as bf
from . import resolver as wildcard_resolver
from .patterns import wildcard_base


@dataclass
class DeepStageResult:
    discovered: set[str] = field(default_factory=set)
    visited_bases: set[str] = field(default_factory=set)
    per_base_stats: dict[str, bf.BruteforceStats] = field(default_factory=dict)
    depth_reached: int = 0


def deep_enumerate(
    wildcard_patterns: set[str],
    wordlist: list[str],
    *,
    max_depth: int = 2,
    concurrency: int = 50,
    timeout: float = 3.0,
    retries: int = 1,
    resolvers: list[str] | None = None,
    rate_limit: float | None = None,
    logger=None,
) -> DeepStageResult:
    result = DeepStageResult()
    if max_depth <= 0:
        return result

    all_bases = {wildcard_base(w) for w in wildcard_patterns}
    all_bases.discard(None)

    # Seed the frontier with only the *top-level* wildcard bases -- a base
    # that is itself a suffix-child of another observed wildcard base (e.g.
    # rpc.testnet.arc.io under *.testnet.arc.io) is reached through
    # recursion once its parent has actually been processed, not seeded
    # directly. That's what makes this "recursive" rather than a flat pass.
    def _is_top_level(base: str) -> bool:
        return not any(other != base and base.endswith("." + other) for other in all_bases)

    frontier = {b for b in all_bases if _is_top_level(b)}

    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        next_frontier: set[str] = set()

        for base in sorted(frontier):
            if base in result.visited_bases:
                continue
            result.visited_bases.add(base)

            wc_ip = wildcard_resolver.detect_wildcard(base, resolvers=resolvers, timeout=timeout)
            if logger:
                note = f" (wildcard catch-all: {', '.join(sorted(wc_ip))})" if wc_ip else ""
                logger.info(f"  deep[{depth}/{max_depth}] {base}{note}")

            bf_result = bf.bruteforce(
                base,
                wordlist,
                concurrency=concurrency,
                timeout=timeout,
                retries=retries,
                resolvers=resolvers,
                rate_limit=rate_limit,
                wildcard_ip=wc_ip,
            )
            result.per_base_stats[base] = bf_result.stats
            result.discovered |= bf_result.found

            # Only recurse into a *.child.base pattern if it was actually
            # present in the original wildcard data -- never speculative.
            for w in wildcard_patterns:
                child_base = wildcard_base(w)
                if (
                    child_base
                    and child_base != base
                    and child_base.endswith("." + base)
                    and child_base not in result.visited_bases
                ):
                    next_frontier.add(child_base)

        frontier = next_frontier - result.visited_bases

    result.depth_reached = depth
    return result
