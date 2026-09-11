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
    wildcard_ip: str | None = None
    sources: dict = field(default_factory=dict)   # name -> {ok, count, message}
    total_subdomains: int = 0
    resolved: int = 0
    alive: int = 0
    output_dir: str = ""

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    def to_markdown(self, path: Path) -> None:
        lines = [
            f"# UltraRecon report — `{self.domain}`",
            "",
            f"- **Started:** {self.started_at}",
            f"- **Finished:** {self.finished_at}",
            f"- **Wildcard DNS:** {self.wildcard_ip or 'not detected'}",
            f"- **Total unique subdomains:** {self.total_subdomains}",
            f"- **Resolved (DNS A record):** {self.resolved}",
            f"- **Alive (HTTP/HTTPS):** {self.alive}",
            "",
            "## Sources",
            "",
            "| Source | Status | Found | Notes |",
            "|---|---|---|---|",
        ]
        for name, info in self.sources.items():
            status = "✅" if info.get("ok") else "❌"
            lines.append(
                f"| {name} | {status} | {info.get('count', 0)} | {info.get('message', '')} |"
            )
        lines.append("")
        lines.append(f"Full artifacts are in `{self.output_dir}`.")
        path.write_text("\n".join(lines))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
