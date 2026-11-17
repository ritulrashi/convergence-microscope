"""E1: bring-up time to the first passing `verify`, for every topology-mode pair.

Per trial: destroy any previous lab, deploy, then run verify repeatedly.
bringup_s = deploy time + time from verify start to the start of the first
passing attempt. Output: results/e1/e1.jsonl (machine record, one record per
trial, one summary record per pair). Failed trials are kept and marked invalid.
"""

from __future__ import annotations

from pathlib import Path

import typer

from bench.common import RESULTS, cpu_sample, cpu_util, loadavg1, summarize
from labctl import lab as labmod
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode

INTENTS = {"t1": "intent/t1-leafspine.yaml", "t2": "intent/t2-mesh.yaml"}


def trial(lab: labmod.Lab, timeout: float) -> dict:
    try:
        labmod.down(lab)
    except labmod.CmdError:
        pass
    c0 = cpu_sample()
    deploy_s = labmod.up(lab)
    res, to_pass, attempts = verify_wait(lab, timeout)
    return {
        "deploy_s": round(deploy_s, 3),
        "verify_s": round(to_pass, 3) if res.ok else None,
        "bringup_s": round(deploy_s + to_pass, 3) if res.ok else None,
        "attempts": attempts,
        "failures": res.failures[:5],
        "cpu_util": round(cpu_util(c0, cpu_sample()), 3),
        "loadavg1_end": loadavg1(),
        "valid": res.ok,
        "invalid_reason": None if res.ok else f"verify did not pass within {timeout}s",
    }


def main(
    trials: int = 10,
    out: Path = RESULTS / "e1" / "e1.jsonl",
    timeout: float = 180,
    topos: str = "t1,t2",
    modes: str = "ebgp,ospf,isis",
) -> None:
    with ResultWriter(out) as w:
        for topo in topos.split(","):
            for mode in modes.split(","):
                lab = labmod.load(Path(INTENTS[topo]), Mode(mode), False)
                ok: list[float] = []
                for i in range(trials):
                    rec = {
                        "record": "trial",
                        "experiment": "E1",
                        "topology": topo,
                        "mode": mode,
                        "bfd": False,
                        "trial": i,
                        **trial(lab, timeout),
                    }
                    w.write(rec)
                    if rec["valid"]:
                        ok.append(rec["bringup_s"])
                    typer.echo(
                        f"{topo}-{mode} #{i}: bringup {rec['bringup_s']} s "
                        f"(deploy {rec['deploy_s']} s) valid={rec['valid']}"
                    )
                labmod.down(lab)
                w.write(
                    {
                        "record": "summary",
                        "experiment": "E1",
                        "topology": topo,
                        "mode": mode,
                        "metric": "bringup_s",
                        "excluded_invalid": trials - len(ok),
                        **summarize(ok),
                    }
                )


if __name__ == "__main__":
    typer.run(main)
