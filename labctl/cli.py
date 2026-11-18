"""labctl: bring labs up and down, verify them, snapshot them, check drift."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from labctl import lab as labmod
from labctl.drift import diff as drift_diff
from labctl.results import ResultWriter
from labctl.snapshot import write_snapshot
from labctl.verify import verify_wait
from labgen.model import Mode

app = typer.Typer(add_completion=False, no_args_is_help=True)

IntentArg = typer.Argument(..., help="intent YAML, e.g. intent/t1-leafspine.yaml")
ModeOpt = typer.Option(None, help="override routing.mode")
BfdOpt = typer.Option(None, "--bfd/--no-bfd", help="override routing.bfd")


@app.command()
def up(
    intent: Path = IntentArg,
    mode: Mode | None = ModeOpt,
    bfd: bool | None = BfdOpt,
    wait: float = typer.Option(0, help="then verify, retrying for up to this many seconds"),
) -> None:
    """Generate configs and deploy the lab."""
    lab = labmod.load(intent, mode, bfd)
    secs = labmod.up(lab)
    typer.echo(f"deployed {lab.name} in {secs:.1f}s")
    if wait > 0:
        _verify(lab, wait)


@app.command()
def down(intent: Path = IntentArg, mode: Mode | None = ModeOpt, bfd: bool | None = BfdOpt) -> None:
    """Destroy the lab."""
    lab = labmod.load(intent, mode, bfd)
    labmod.down(lab)
    typer.echo(f"destroyed {lab.name}")


def _verify(lab: labmod.Lab, wait: float, out_path: Path | None = None) -> None:
    res, t, attempts = verify_wait(lab, wait)
    out = {
        "record": "verify",
        "lab": lab.name,
        "ok": res.ok,
        "checks": res.checks,
        "failures": res.failures,
        "attempts": attempts,
        "seconds_to_pass": round(t, 3) if res.ok else None,
    }
    typer.echo(json.dumps(out, indent=2))
    if out_path is not None:
        with ResultWriter(out_path) as w:
            w.write(out)
    if not res.ok:
        raise typer.Exit(1)


@app.command()
def verify(
    intent: Path = IntentArg,
    mode: Mode | None = ModeOpt,
    bfd: bool | None = BfdOpt,
    wait: float = typer.Option(0, help="retry for up to this many seconds"),
    out: Path | None = typer.Option(None, help="also write a results JSONL file"),
) -> None:
    """Check sessions/adjacencies, RIBs, ECMP width and full-mesh host ping."""
    _verify(labmod.load(intent, mode, bfd), wait, out)


@app.command()
def diff(intent: Path = IntentArg, mode: Mode | None = ModeOpt, bfd: bool | None = BfdOpt) -> None:
    """Config drift: each router's running config vs its generated frr.conf."""
    lab = labmod.load(intent, mode, bfd)
    drifted = 0
    for r in lab.plan.routers:
        running = lab.exec(r.name, "vtysh", "-c", "show running-config").stdout
        lines = drift_diff((lab.dir / r.name / "frr.conf").read_text(), running, r.name)
        if lines:
            drifted += 1
            typer.echo("\n".join(lines))
    typer.echo(f"{drifted} of {len(lab.plan.routers)} routers drifted")
    if drifted:
        raise typer.Exit(1)


@app.command()
def snapshot(
    intent: Path = IntentArg,
    mode: Mode | None = ModeOpt,
    bfd: bool | None = BfdOpt,
    out: Path = typer.Option(..., help="output JSON path"),
) -> None:
    """Dump every router's kernel routes and nexthop objects."""
    typer.echo(str(write_snapshot(labmod.load(intent, mode, bfd), out)))


@app.command("run")
def run_cmd(
    intent: Path = IntentArg,
    mode: Mode | None = ModeOpt,
    bfd: bool | None = BfdOpt,
    event: str = typer.Option(..., help="carrier_down, silent_down, link_up or node_down"),
    seed: int = typer.Option(0, help="seeds the location choice"),
    location: str | None = typer.Option(None, help="'a-b' (link, acted on at a) or a router"),
    rate: int = typer.Option(500, help="probe pps per host pair (ADR-018)"),
    duration: float = typer.Option(8.0, help="probing seconds"),
    event_at: float = typer.Option(2.0, help="seconds after probing starts"),
    out: Path = typer.Option(Path("results/runs"), help="output root"),
    keep_raw: bool = typer.Option(False, help="keep probes and hops (gzipped)"),
) -> None:
    """One seeded fault-injection run, replayed and reported."""
    from labctl.runner import do_run

    rep = do_run(
        labmod.load(intent, mode, bfd),
        event,
        seed,
        out,
        location,
        rate,
        duration,
        event_at,
        keep_raw=keep_raw,
    )
    typer.echo(
        json.dumps(
            {
                k: rep[k]
                for k in ("run_id", "valid", "lost", "lost_by_cause", "microloops_in_fib", "replay")
            },
            indent=2,
        )
    )


@app.command()
def report(run_dir: Path) -> None:
    """(Re)write report.json and timeline.html for a replayed run."""
    from labctl.report import write_report

    rep = write_report(run_dir)
    typer.echo(json.dumps(rep["lost_by_cause"]))


if __name__ == "__main__":
    app()
