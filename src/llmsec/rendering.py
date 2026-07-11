"""CLI output rendering: human-readable (Rich: tables, colors, a live progress bar) or
machine-readable (--json).

Keeps all print()-ing in one place, at the CLI boundary — core/engine.py and core/runner.py
return data, they never print themselves (see core/engine.py's module docstring). Every CLI
command picks a `Renderer` based on `--json` and calls into it instead of `typer.echo`/`print`
directly, so `--json` is a real, separate output path rather than something scraped out of
human-formatted text.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from llmsec.config import Config
from llmsec.models.campaign import Campaign
from llmsec.models.result import TestResult
from llmsec.models.test_case import TestCase

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}
_STATUS_STYLES: dict[str, str] = {
    "failed": "bold red",
    "passed": "bold green",
    "inconclusive": "yellow",
    "errors": "magenta",
}


class Renderer(ABC):
    """What every CLI command's output path — Rich or JSON — must support."""

    @abstractmethod
    def version(self, version_string: str) -> None: ...

    @abstractmethod
    def config_valid(self, path: Path, cfg: Config) -> None: ...

    @abstractmethod
    def error(self, message: str) -> None: ...

    @abstractmethod
    def list_tests(self, cases: list[TestCase]) -> None: ...

    @abstractmethod
    def scan_progress(self, total: int) -> AbstractContextManager[Callable[[TestResult], None]]:
        """A context manager yielding an `on_result` callback for `core.engine.run_campaign`."""
        ...

    @abstractmethod
    def scan_summary(self, campaign: Campaign, written: dict[str, Path]) -> None: ...

    @abstractmethod
    def report_written(self, written: dict[str, Path]) -> None: ...


class RichRenderer(Renderer):
    """Default, human-facing output: colored tables and a live progress bar."""

    def __init__(self) -> None:
        self.console = Console()
        self.err_console = Console(stderr=True)

    def version(self, version_string: str) -> None:
        self.console.print(f"llmsec {version_string}")

    def config_valid(self, path: Path, cfg: Config) -> None:
        self.console.print(f"[bold green]Configuration is valid:[/bold green] {path}")
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_row("[dim]target[/dim]", cfg.target.base_url)
        formats = ", ".join(cfg.reporting.formats)
        table.add_row("[dim]reporting[/dim]", f"{formats} -> {cfg.reporting.output_directory}")
        self.console.print(table)

    def error(self, message: str) -> None:
        self.err_console.print(f"[bold red]Error:[/bold red] {message}")

    def list_tests(self, cases: list[TestCase]) -> None:
        if not cases:
            self.console.print("No test cases found.")
            return

        table = Table(title=f"{len(cases)} test case(s)")
        table.add_column("ID", style="bold")
        table.add_column("Category")
        table.add_column("Severity")
        table.add_column("Name")
        for case in cases:
            severity_style = _SEVERITY_STYLES.get(case.severity.value, "")
            table.add_row(
                case.id,
                case.category.value,
                f"[{severity_style}]{case.severity.value}[/{severity_style}]",
                case.name,
            )
        self.console.print(table)

    @contextmanager
    def scan_progress(self, total: int) -> Iterator[Callable[[TestResult], None]]:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task_id = progress.add_task("Scanning", total=total)

            def on_result(result: TestResult) -> None:
                progress.update(task_id, advance=1, description=f"Scanning [{result.test_id}]")

            yield on_result

    def scan_summary(self, campaign: Campaign, written: dict[str, Path]) -> None:
        table = Table(title=f"Campaign {campaign.id} ({campaign.suite})")
        table.add_column("Status")
        table.add_column("Count", justify="right")
        counts = {
            "passed": campaign.passed_count,
            "failed": campaign.failed_count,
            "inconclusive": campaign.inconclusive_count,
            "errors": campaign.error_count,
        }
        for status, count in counts.items():
            style = _STATUS_STYLES.get(status, "")
            table.add_row(f"[{style}]{status}[/{style}]", str(count))
        self.console.print(table)

        for fmt, path in written.items():
            self.console.print(f"  [dim]{fmt:<10}[/dim]: {path}")

    def report_written(self, written: dict[str, Path]) -> None:
        for fmt, path in written.items():
            self.console.print(f"[bold]{fmt:<10}[/bold]: {path}")


class JsonRenderer(Renderer):
    """Machine-readable output for scripting/CI: one JSON object per command on stdout.

    `scan_progress` intentionally shows no live progress — stdout must stay a single clean JSON
    document, so progress isn't observable in this mode (use the default Rich renderer, whose
    progress bar renders to stderr-safe terminal control codes, for interactive use).
    """

    def _emit(self, payload: dict[str, Any]) -> None:
        print(json.dumps(payload, default=str))

    def version(self, version_string: str) -> None:
        self._emit({"version": version_string})

    def config_valid(self, path: Path, cfg: Config) -> None:
        self._emit(
            {
                "valid": True,
                "path": str(path),
                "target": cfg.target.base_url,
                "reporting_formats": cfg.reporting.formats,
                "output_directory": cfg.reporting.output_directory,
            }
        )

    def error(self, message: str) -> None:
        self._emit({"error": message})

    def list_tests(self, cases: list[TestCase]) -> None:
        self._emit(
            {
                "count": len(cases),
                "test_cases": [
                    {
                        "id": c.id,
                        "category": c.category.value,
                        "severity": c.severity.value,
                        "name": c.name,
                    }
                    for c in cases
                ],
            }
        )

    @contextmanager
    def scan_progress(self, total: int) -> Iterator[Callable[[TestResult], None]]:
        def on_result(result: TestResult) -> None:
            return None

        yield on_result

    def scan_summary(self, campaign: Campaign, written: dict[str, Path]) -> None:
        self._emit(
            {
                "campaign_id": campaign.id,
                "suite": campaign.suite,
                "total_tests": campaign.total_tests,
                "passed": campaign.passed_count,
                "failed": campaign.failed_count,
                "inconclusive": campaign.inconclusive_count,
                "errors": campaign.error_count,
                "reports": {fmt: str(path) for fmt, path in written.items()},
            }
        )

    def report_written(self, written: dict[str, Path]) -> None:
        self._emit({"reports": {fmt: str(path) for fmt, path in written.items()}})


def get_renderer(*, json_output: bool) -> Renderer:
    return JsonRenderer() if json_output else RichRenderer()
