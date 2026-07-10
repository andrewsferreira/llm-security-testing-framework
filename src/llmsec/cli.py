"""Command-line entry point for the llmsec framework."""

from __future__ import annotations

from pathlib import Path

import typer

from llmsec import __version__
from llmsec.config import load_config
from llmsec.constants import DEFAULT_CONFIG_PATH, ExitCode
from llmsec.exceptions import ConfigError, LlmsecError
from llmsec.logging import configure_logging

app = typer.Typer(
    name="llmsec",
    help="Security testing framework for LLM-backed chatbots, agents, and tool-calling APIs. "
    "Use only against systems you own or are explicitly authorized to test.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed llmsec version."""
    typer.echo(f"llmsec {__version__}")


@app.command("validate-config")
def validate_config(
    config: Path = typer.Option(
        Path(DEFAULT_CONFIG_PATH), "--config", help="Path to a YAML configuration file."
    ),
) -> None:
    """Validate a YAML configuration file without running anything."""
    try:
        loaded = load_config(config)
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    typer.secho(f"Configuration is valid: {config}", fg=typer.colors.GREEN)
    typer.echo(f"  target:    {loaded.target.base_url}")
    formats = ", ".join(loaded.reporting.formats)
    typer.echo(f"  reporting: {formats} -> {loaded.reporting.output_directory}")


@app.command("list-tests")
def list_tests(
    category: str | None = typer.Option(
        None, "--category", help="Filter by attack category (e.g. jailbreak)."
    ),
) -> None:
    """List the available test cases loaded from the payload registry."""
    from llmsec.core.registry import load_all_test_cases  # deferred: Phase 5 module

    cases = load_all_test_cases()
    if category:
        cases = [c for c in cases if c.category.value == category]

    if not cases:
        typer.echo("No test cases found.")
        return

    for case in cases:
        label = f"[{case.category.value:<28}] {case.severity.value:<8}"
        typer.echo(f"{case.id:<12} {label} {case.name}")
    typer.echo(f"\n{len(cases)} test case(s).")


@app.command()
def scan(
    target: str | None = typer.Option(None, "--target", help="Override the target base URL."),
    suite: str = typer.Option("all", "--suite", help="Attack category to run, or 'all'."),
    config: Path = typer.Option(
        Path(DEFAULT_CONFIG_PATH), "--config", help="Path to a YAML configuration file."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Directory to write reports to (overrides config)."
    ),
) -> None:
    """Run a security test campaign against a target."""
    configure_logging()

    try:
        cfg = load_config(config)
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    if target:
        cfg.target.base_url = target
    if output:
        cfg.reporting.output_directory = str(output)

    from llmsec.core.engine import run_campaign  # deferred: Phase 4 module

    try:
        exit_code = run_campaign(cfg, suite=suite)
    except LlmsecError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=ExitCode.TARGET_ERROR) from exc

    raise typer.Exit(code=exit_code)


@app.command()
def report(
    input_path: Path = typer.Option(
        ..., "--input", help="Path to a results.json file produced by `llmsec scan`."
    ),
    formats: list[str] = typer.Option(
        ["markdown", "html"], "--format", help="Report format(s) to (re)generate."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Directory to write reports to (defaults to the input's directory)."
    ),
) -> None:
    """Regenerate report(s) from a previously saved results.json file."""
    from llmsec.core.engine import regenerate_reports  # deferred: Phase 6 module

    regenerate_reports(input_path, formats=formats, output_dir=output)


if __name__ == "__main__":
    app()
