"""E4: SPF timer skew on T2 (emulated heterogeneity).

The T2 intent is built so that when r3-r4 fails, r3's new path to r4 goes
through r2 while r2's old path went through r3. If r3 recomputes before r2,
packets for r4 bounce between them: a microloop. Here r2's SPF delay is set
SKEW ms longer than every other router's, emulating a slower router. Real
routers differ in CPU and implementation; these labs differ only by timer,
and every result is labelled that way.

Per setting: TRIALS carrier_down runs on r3-r4 (acted on at r3), OSPF and
IS-IS. Output: results/e4/e4.jsonl and results/e4/runs/.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from bench.common import RESULTS, summarize
from bench.e3_failures import flatten
from labctl import lab as labmod
from labctl.procs import build_go
from labctl.results import ResultWriter
from labctl.runner import do_run
from labctl.verify import verify_wait
from labgen.model import Mode
from labgen.render import REPO

BASE_MS = 50
SLOW = "r2"


def skewed_intent(skew_ms: int) -> Path:
    d = yaml.safe_load((REPO / "intent/t2-mesh.yaml").read_text())
    d["name"] = f"t2-skew{skew_ms}"
    for n in d["nodes"]:
        if n["name"] == SLOW:
            n["timers"] = {"spf_delay_ms": BASE_MS + skew_ms, "isis_spf_init_ms": BASE_MS + skew_ms}
    p = REPO / "generated" / "intents" / f"t2-skew{skew_ms}.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(d, sort_keys=False))
    return p


def main(
    trials: int = 20,
    skews: str = "0,25,50,100,200,400",
    modes: str = "ospf,isis",
    out_dir: Path = RESULTS / "e4",
) -> None:
    build_go()
    with ResultWriter(out_dir / "e4.jsonl") as w:
        for mode in modes.split(","):
            for skew in [int(s) for s in skews.split(",")]:
                lab = labmod.load(skewed_intent(skew), Mode(mode), False)
                try:
                    labmod.down(lab)
                except labmod.CmdError:
                    pass
                labmod.up(lab)
                res, _, _ = verify_wait(lab, 180)
                if not res.ok:
                    w.write(
                        {
                            "record": "setting_skipped",
                            "mode": mode,
                            "skew_ms": skew,
                            "reason": str(res.failures[:3]),
                        }
                    )
                    labmod.down(lab)
                    continue
                rows = []
                for i in range(trials):
                    rep = do_run(
                        lab,
                        "carrier_down",
                        seed=i,
                        out_root=out_dir / "runs",
                        location="r3-r4",
                        keep_raw=i == 0,
                    )
                    run = json.loads((out_dir / "runs" / rep["run_id"] / "run.json").read_text())
                    row = {
                        "record": "run",
                        "label": "emulated heterogeneity (SPF timer skew)",
                        "mode": mode,
                        "skew_ms": skew,
                        "slow_router": SLOW,
                        "seed": i,
                        "run_id": rep["run_id"],
                        "valid": rep["valid"],
                        "invalid_reasons": rep["invalid_reasons"],
                        "cpu_util": run["cpu_util"],
                        "microloop_routers": sorted(
                            {",".join(m["routers"]) for m in rep["microloops"]}
                        ),
                        **flatten(rep),
                    }
                    rows.append(row)
                    w.write(row)
                    typer.echo(
                        f"{mode} skew {skew} #{i}: loops {row['microloops_in_fib']} "
                        f"max {row['max_microloop_ms']} ms, lost loop "
                        f"{row['lost_microloop']} bh {row['lost_blackhole']}"
                    )
                ok = [r for r in rows if r["valid"]]
                summ = {
                    "record": "summary",
                    "label": "emulated heterogeneity (SPF timer skew)",
                    "mode": mode,
                    "skew_ms": skew,
                    "runs": len(rows),
                    "valid": len(ok),
                    "runs_with_microloop": sum(1 for r in ok if r["microloops_in_fib"] > 0),
                    "excluded": [
                        {"run_id": r["run_id"], "reasons": r["invalid_reasons"]}
                        for r in rows
                        if not r["valid"]
                    ],
                }
                for m in (
                    "microloops_in_fib",
                    "max_microloop_ms",
                    "lost_microloop",
                    "lost_blackhole",
                    "lost",
                    "convergence_last_loss_ms",
                ):
                    summ[m] = summarize([float(r[m]) for r in ok if r.get(m) is not None])
                w.write(summ)
                labmod.down(lab)


if __name__ == "__main__":
    typer.run(main)
