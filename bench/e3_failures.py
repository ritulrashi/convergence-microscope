"""E3: failure matrix.

topology x mode x event (carrier_down, silent_down, link_up, node_down) x BFD
on/off, TRIALS runs per cell, trial i uses seed i (location chosen from the
seed, so every cell sees the same sequence of locations). Per run: packets
lost by cause, loss window, microloop count and duration, convergence time.

Output: results/e3/e3.jsonl (machine record, one record per run, one summary
per cell) and results/e3/runs/<run_id>/ (see ADR-015). Invalid runs are kept
and excluded from summaries with their reason. Cells can be trimmed with
--topos/--modes/--events/--bfd; FINDINGS.md says which and why.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer

from bench.common import RESULTS, summarize
from labctl import lab as labmod
from labctl.events import EVENTS
from labctl.procs import build_go
from labctl.results import ResultWriter
from labctl.runner import do_run
from labctl.verify import verify_wait
from labgen.model import Mode

INTENTS = {"t1": "intent/t1-leafspine.yaml", "t2": "intent/t2-mesh.yaml"}
METRICS = (
    "lost",
    "lost_blackhole",
    "lost_microloop",
    "lost_other",
    "lost_unknown",
    "max_flow_window_ms",
    "microloops_in_fib",
    "convergence_last_fib_change_ms",
    "convergence_last_loss_ms",
)


def flatten(rep: dict) -> dict:
    out = {k: rep.get(k) for k in METRICS if k in rep}
    for c, n in rep["lost_by_cause"].items():
        out[f"lost_{c}"] = n
    out["max_microloop_ms"] = max((m["duration_ms"] for m in rep["microloops"]), default=0.0)
    out["fate_agreement"] = rep["replay"]["fate_agreement"]
    out["path_consistency"] = rep["replay"]["path_consistency"]
    return out


def main(
    trials: int = 20,
    topos: str = "t1,t2",
    modes: str = "ebgp,ospf,isis",
    events: str = ",".join(EVENTS),
    bfd: str = "off,on",
    keep_raw_first: bool = True,
    out_dir: Path = RESULTS / "e3",
) -> None:
    build_go()
    out_dir.mkdir(parents=True, exist_ok=True)
    with ResultWriter(out_dir / "e3.jsonl") as w:
        for topo in topos.split(","):
            for mode in modes.split(","):
                for b in bfd.split(","):
                    lab = labmod.load(Path(INTENTS[topo]), Mode(mode), b == "on")
                    try:
                        labmod.down(lab)
                    except labmod.CmdError:
                        pass
                    labmod.up(lab)
                    res, _, _ = verify_wait(lab, 180)
                    if not res.ok:
                        w.write(
                            {
                                "record": "cell_skipped",
                                "topology": topo,
                                "mode": mode,
                                "bfd": b == "on",
                                "reason": f"verify failed: {res.failures[:3]}",
                            }
                        )
                        labmod.down(lab)
                        continue
                    for event in events.split(","):
                        rows = []
                        for i in range(trials):
                            t0 = time.monotonic()
                            try:
                                rep = do_run(
                                    lab,
                                    event,
                                    seed=i,
                                    out_root=out_dir / "runs",
                                    keep_raw=keep_raw_first and i == 0,
                                )
                            except Exception as e:  # keep going; record the failure
                                w.write(
                                    {
                                        "record": "run_error",
                                        "topology": topo,
                                        "mode": mode,
                                        "bfd": b == "on",
                                        "event": event,
                                        "seed": i,
                                        "error": str(e)[:500],
                                    }
                                )
                                verify_wait(lab, 180)
                                continue
                            run = json.loads(
                                (out_dir / "runs" / rep["run_id"] / "run.json").read_text()
                            )
                            row = {
                                "record": "run",
                                "topology": topo,
                                "mode": mode,
                                "bfd": b == "on",
                                "event": event,
                                "seed": i,
                                "run_id": rep["run_id"],
                                "location": run["location"],
                                "valid": rep["valid"],
                                "invalid_reasons": rep["invalid_reasons"],
                                "cpu_util": run["cpu_util"],
                                "loadavg1": run["loadavg1"],
                                "wall_s": round(time.monotonic() - t0, 1),
                                **flatten(rep),
                            }
                            rows.append(row)
                            w.write(row)
                            typer.echo(
                                f"{rep['run_id']}: lost {row['lost']} "
                                f"(bh {row['lost_blackhole']}, loop {row['lost_microloop']}) "
                                f"valid={row['valid']} {row['wall_s']}s"
                            )
                        ok = [r for r in rows if r["valid"]]
                        summ = {
                            "record": "summary",
                            "topology": topo,
                            "mode": mode,
                            "bfd": b == "on",
                            "event": event,
                            "runs": len(rows),
                            "valid": len(ok),
                            "excluded": [
                                {"run_id": r["run_id"], "reasons": r["invalid_reasons"]}
                                for r in rows
                                if not r["valid"]
                            ],
                        }
                        for m in (*METRICS, "max_microloop_ms"):
                            vals = [float(r[m]) for r in ok if r.get(m) is not None]
                            summ[m] = summarize(vals)
                        w.write(summ)
                    labmod.down(lab)


if __name__ == "__main__":
    typer.run(main)
