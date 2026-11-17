"""labctl: bring labs up and down, verify them, snapshot them."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from labctl import lab as labmod
from labctl.snapshot import write_snapshot
from labctl.verify import verify_wait
from labgen.model import Mode

app = typer.Typer(add_completion=False, no_args_is_help=True)

IntentArg = typer.Argument(..., help="intent YAML, e.g. intent/t1-leafspine.yaml")
ModeOpt = typer.Option(None, help="override routing.mode")


@app.command()
def up(intent: Path = IntentArg, mode: Mode | None = ModeOpt,
       wait: float = typer.Option(0, help="then verify, retrying for up to this many seconds")
       ) -> None:
    """Generate configs and deploy the lab."""
    lab = labmod.load(intent, mode)
    secs = labmod.up(lab)
    typer.echo(f"deployed {lab.name} in {secs:.1f}s")
    if wait > 0:
        _verify(lab, wait)


@app.command()
def down(intent: Path = IntentArg, mode: Mode | None = ModeOpt) -> None:
    """Destroy the lab."""
    lab = labmod.load(intent, mode)
    labmod.down(lab)
    typer.echo(f"destroyed {lab.name}")


def _verify(lab: labmod.Lab, wait: float) -> None:
    res, t, attempts = verify_wait(lab, wait)
    out = {"ok": res.ok, "checks": res.checks, "failures": res.failures, "attempts": attempts,
           "seconds_to_pass": round(t, 3) if res.ok else None}
    typer.echo(json.dumps(out, indent=2))
    if not res.ok:
        raise typer.Exit(1)


@app.command()
def verify(intent: Path = IntentArg, mode: Mode | None = ModeOpt,
           wait: float = typer.Option(0, help="retry for up to this many seconds")) -> None:
    """Check sessions/adjacencies, RIBs, ECMP width and full-mesh host ping."""
    _verify(labmod.load(intent, mode), wait)


@app.command()
def snapshot(intent: Path = IntentArg, mode: Mode | None = ModeOpt,
             out: Path = typer.Option(..., help="output JSON path")) -> None:
    """Dump every router's kernel routes and nexthop objects."""
    typer.echo(str(write_snapshot(labmod.load(intent, mode), out)))


if __name__ == "__main__":
    app()
