"""Command-line entry point for the llmsec framework."""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from llmsec import __version__
from llmsec.config import load_config
from llmsec.constants import DEFAULT_CONFIG_PATH, ExitCode
from llmsec.exceptions import ConfigError, LlmsecError
from llmsec.logging import configure_logging
from llmsec.rendering import get_renderer

app = typer.Typer(
    name="llmsec",
    help="Security testing framework for LLM-backed chatbots, agents, and tool-calling APIs. "
    "Use only against systems you own or are explicitly authorized to test.",
    no_args_is_help=True,
)

_JSON_OPTION = typer.Option(
    False, "--json", help="Emit machine-readable JSON instead of human-readable output."
)
_VERBOSE_OPTION = typer.Option(False, "--verbose", help="Show INFO-level logs on stderr.")
_DEBUG_OPTION = typer.Option(
    False, "--debug", help="Show DEBUG-level logs on stderr (implies --verbose)."
)


def _log_level(*, verbose: bool, debug: bool) -> int:
    if debug:
        return logging.DEBUG
    if verbose:
        return logging.INFO
    return logging.WARNING


@app.command()
def version(json_output: bool = _JSON_OPTION) -> None:
    """Print the installed llmsec version."""
    get_renderer(json_output=json_output).version(__version__)


@app.command("validate-config")
def validate_config(
    config: Path = typer.Option(
        Path(DEFAULT_CONFIG_PATH), "--config", help="Path to a YAML configuration file."
    ),
    json_output: bool = _JSON_OPTION,
) -> None:
    """Validate a YAML configuration file without running anything."""
    renderer = get_renderer(json_output=json_output)
    try:
        loaded = load_config(config)
    except ConfigError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    renderer.config_valid(config, loaded)


@app.command("list-tests")
def list_tests(
    category: str | None = typer.Option(
        None, "--category", help="Filter by attack category (e.g. jailbreak)."
    ),
    json_output: bool = _JSON_OPTION,
) -> None:
    """List the available test cases loaded from the payload registry."""
    from llmsec.core.registry import load_all_test_cases

    cases = load_all_test_cases()
    if category:
        cases = [c for c in cases if c.category.value == category]

    get_renderer(json_output=json_output).list_tests(cases)


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
    json_output: bool = _JSON_OPTION,
    verbose: bool = _VERBOSE_OPTION,
    debug: bool = _DEBUG_OPTION,
) -> None:
    """Run a security test campaign against a target."""
    configure_logging(level=_log_level(verbose=verbose, debug=debug))
    renderer = get_renderer(json_output=json_output)

    try:
        cfg = load_config(config)
    except ConfigError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    if target:
        cfg.target.base_url = target
    if output:
        cfg.reporting.output_directory = str(output)

    from llmsec.core.engine import run_campaign
    from llmsec.core.registry import load_all_test_cases, select_suite

    test_cases = select_suite(load_all_test_cases(), suite)
    if not test_cases:
        renderer.error(f"No test cases matched suite {suite!r}.")
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    try:
        with renderer.scan_progress(len(test_cases)) as on_result:
            campaign, written = run_campaign(
                cfg, suite=suite, test_cases=test_cases, on_result=on_result
            )
    except LlmsecError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.TARGET_ERROR) from exc

    renderer.scan_summary(campaign, written)
    exit_code = ExitCode.FINDINGS if campaign.failed_count > 0 else ExitCode.SUCCESS
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
    json_output: bool = _JSON_OPTION,
) -> None:
    """Regenerate report(s) from a previously saved results.json file."""
    from llmsec.constants import SUPPORTED_REPORT_FORMATS
    from llmsec.core.engine import regenerate_reports

    renderer = get_renderer(json_output=json_output)

    unknown = set(formats) - SUPPORTED_REPORT_FORMATS
    if unknown:
        renderer.error(
            f"Unsupported report format(s): {sorted(unknown)}. "
            f"Supported: {sorted(SUPPORTED_REPORT_FORMATS)}."
        )
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    try:
        written = regenerate_reports(input_path, formats=formats, output_dir=output)
    except LlmsecError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    renderer.report_written(written)


@app.command()
def compare(
    input_paths: list[Path] = typer.Option(
        ...,
        "--input",
        help="Path to a results.json file (repeat --input for each campaign; at least 2).",
    ),
    formats: list[str] = typer.Option(
        ["markdown", "html"], "--format", help="Comparison format(s) to generate."
    ),
    output: Path = typer.Option(
        Path("reports/comparison"), "--output", help="Directory to write the comparison to."
    ),
    json_output: bool = _JSON_OPTION,
) -> None:
    """Compare 2+ previously saved campaigns side by side (e.g. different providers, or a lab's
    vulnerable vs. hardened mode) — one report per campaign is not enough to see how they
    differ; this renders category/severity distributions next to each other."""
    from llmsec.constants import SUPPORTED_COMPARISON_FORMATS
    from llmsec.core.engine import compare_campaign_reports

    renderer = get_renderer(json_output=json_output)

    if len(input_paths) < 2:
        renderer.error("--input must be given at least twice (2+ campaigns to compare).")
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    unknown = set(formats) - SUPPORTED_COMPARISON_FORMATS
    if unknown:
        renderer.error(
            f"Unsupported comparison format(s): {sorted(unknown)}. "
            f"Supported: {sorted(SUPPORTED_COMPARISON_FORMATS)}."
        )
        raise typer.Exit(code=ExitCode.USAGE_ERROR)

    try:
        written = compare_campaign_reports(input_paths, formats=formats, output_dir=output)
    except LlmsecError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    renderer.report_written(written)


@app.command()
def dashboard(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Directory to scan recursively for results.json files.",
    ),
    output: Path = typer.Option(
        Path("reports/dashboard.html"), "--output", help="Path to write the dashboard HTML page."
    ),
    json_output: bool = _JSON_OPTION,
) -> None:
    """Aggregate every campaign report found under --reports-dir into one dashboard page.

    Computed fresh from whatever results.json files exist on disk each time this runs — no
    database, no persistent service. Re-run after new scans to refresh."""
    from llmsec.core.engine import build_dashboard_report

    renderer = get_renderer(json_output=json_output)

    try:
        written_path = build_dashboard_report(reports_dir, output_path=output)
    except LlmsecError as exc:
        renderer.error(str(exc))
        raise typer.Exit(code=ExitCode.USAGE_ERROR) from exc

    renderer.report_written({"html": written_path})


if __name__ == "__main__":
    app()
