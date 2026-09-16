from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ScanReport:
    domain: str
    started_at: str
    finished_at: str = ""
    wildcard_ip: list[str] | None = None
    sources: dict = field(default_factory=dict)   # name -> {ok, count, message}
    phases: dict = field(default_factory=dict)     # phase name -> seconds elapsed
    total_subdomains: int = 0                       # raw merged candidates, pre-resolution
    resolved: int = 0                                # == "verified" count written to 1_subdomains.txt
    alive: int = 0
    wildcards_detected: int = 0
    errors: int = 0
    targets: int = 1
    output_dir: str = ""

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    def to_markdown(self, path: Path) -> None:
        lines = [
            f"# UltraRecon report -- `{self.domain}`",
            "",
            f"- **Started:** {self.started_at}",
            f"- **Finished:** {self.finished_at}",
            f"- **Targets:** {self.targets}",
            f"- **Wildcard DNS (top-level):** {', '.join(self.wildcard_ip) if self.wildcard_ip else 'not detected'}",
            f"- **Raw candidates found:** {self.total_subdomains}",
            f"- **Verified subdomains (resolved):** {self.resolved}",
            f"- **Wildcard patterns detected:** {self.wildcards_detected}",
            f"- **Alive (HTTP/HTTPS):** {self.alive}",
            f"- **Errors encountered:** {self.errors}",
            "",
            "## Phase timings",
            "",
            "| Phase | Duration |",
            "|---|---|",
        ]
        for name, seconds in self.phases.items():
            lines.append(f"| {name} | {seconds:.2f}s |")

        lines += [
            "",
            "## Sources",
            "",
            "| Source | Status | Found | Notes |",
            "|---|---|---|---|",
        ]
        for name, info in self.sources.items():
            status = "\u2705" if info.get("ok") else "\u274c"
            lines.append(
                f"| {name} | {status} | {info.get('count', 0)} | {info.get('message', '')} |"
            )
        lines.append("")
        lines.append(f"Full artifacts are in `{self.output_dir}`.")
        path.write_text("\n".join(lines))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
