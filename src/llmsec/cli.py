"""Command-line entry point for the llmsec framework (fleshed out in Phase 2)."""

import typer

from llmsec import __version__

app = typer.Typer(
    name="llmsec",
    help="Security testing framework for LLM-backed chatbots, agents, and tool-calling APIs.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed llmsec version."""
    typer.echo(f"llmsec {__version__}")


if __name__ == "__main__":
    app()
