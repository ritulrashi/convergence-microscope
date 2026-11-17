"""labgen: render an intent file into lab configs."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from labctl.machine import frr_image
from labgen.ipam import PoolExhausted
from labgen.model import Mode, load_intent
from labgen.render import REPO, generate

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def main() -> None:
    """Config generator for convergence-microscope labs."""


@app.command()
def render(
    intent: Path,
    mode: Mode | None = typer.Option(None, help="override routing.mode"),
    out: Path = typer.Option(REPO / "generated", help="output root"),
) -> None:
    """Validate INTENT and write generated/<name>-<mode>/."""
    try:
        path = generate(load_intent(intent), mode, out, frr_image())
    except (ValidationError, PoolExhausted) as e:
        typer.echo(f"invalid intent {intent}:\n{e}", err=True)
        raise typer.Exit(1) from e
    typer.echo(str(path))


if __name__ == "__main__":
    app()
