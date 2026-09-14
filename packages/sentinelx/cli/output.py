"""Terminal output.

Data goes to stdout, diagnostics to stderr, so ``sentinelx detections --json | jq``
always receives clean JSON. Colour is disabled automatically when output is piped.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = [
    "SEVERITY_STYLE",
    "console",
    "emit_json",
    "err",
    "fail",
    "risk_text",
    "safety_panel",
    "severity_text",
    "table",
]

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "informational": "dim",
}


def emit_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")


def severity_text(severity: str) -> Text:
    return Text(f" {severity.upper()} ", style=SEVERITY_STYLE.get(severity, ""))


def risk_text(score: float | None) -> Text:
    if score is None:
        return Text("-", style="dim")
    style = (
        "bold red"
        if score > 80
        else "red"
        if score > 60
        else "yellow"
        if score > 40
        else "cyan"
        if score > 20
        else "dim"
    )
    return Text(f"{score:5.1f}", style=style)


def table(
    title: str, columns: Sequence[str], rows: Iterable[Sequence[Any]], *, caption: str | None = None
) -> Table:
    result = Table(
        title=title, caption=caption, header_style="bold", expand=False, show_lines=False
    )
    for column in columns:
        result.add_column(column, overflow="fold")
    for row in rows:
        result.add_row(
            *[
                cell if isinstance(cell, Text) else Text("-" if cell is None else str(cell))
                for cell in row
            ]
        )
    return result


def safety_panel(banner: str) -> Panel:
    style = (
        "bold white on red"
        if banner.startswith("PREVENTION ACTIVE")
        else "yellow"
        if banner.startswith("DRY RUN")
        else "green"
    )
    return Panel(Text(banner, style=style), title="Safety posture", expand=False)


def fail(message: str, code: int = 1) -> None:
    """Print an error to stderr and exit. Only called from command entry points."""
    import typer

    err.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(code)
