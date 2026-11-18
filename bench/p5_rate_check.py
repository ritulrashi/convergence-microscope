"""Which probe rate keeps runs valid under full instrumentation?

E0 part A found the 5 ms send-schedule tolerance broken in 4 of 10 trials at
1,000 pps per pair with the tracer on. This check mirrors a real `labctl run`
(recorders on every router, tracer, per-packet probe logging, 8 s) with no
fault, on T1 eBGP all 12 pairs, at several rates, TRIALS each. Output:
results/p5/rate_check.jsonl.
"""

from __future__ import annotations

from pathlib import Path

import typer

from bench.common import RESULTS, cpu_sample, cpu_util, summarize
from labctl import lab as labmod
from labctl.procs import (
    build_go,
    start_probers,
    start_recorders,
    start_tracer,
    stop_recorders,
    stop_tracer,
    wait_probers,
)
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode

SCRATCH = Path("/tmp/cm-rate")


def main(
    trials: int = 10,
    rates: str = "250,500,1000",
    duration: float = 8.0,
    out: Path = RESULTS / "p5" / "rate_check.jsonl",
) -> None:
    build_go()
    lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
    labmod.up(lab)
    try:
        res, _, _ = verify_wait(lab, 120)
        if not res.ok:
            raise SystemExit(f"lab did not verify: {res.failures}")
        with ResultWriter(out) as w:
            for rate in [int(x) for x in rates.split(",")]:
                valid, lates = 0, []
                for i in range(trials):
                    recs = start_recorders(lab, SCRATCH / "rec")
                    tr = start_tracer(lab, SCRATCH / "hops.jsonl")
                    c0 = cpu_sample()
                    pr = start_probers(lab, rate, duration)
                    ps = wait_probers(lab, pr, SCRATCH / "probes.jsonl", timeout_s=duration + 60)
                    cpu = cpu_util(c0, cpu_sample())
                    rs = stop_recorders(recs)
                    ts = stop_tracer(tr)
                    ok = (
                        all(p.get("valid") for p in ps)
                        and all(r.get("valid") for r in rs)
                        and ts.get("valid", False)
                    )
                    valid += ok
                    late = max(p.get("max_late_ns", 0) for p in ps)
                    lates.append(late / 1e6)
                    w.write(
                        {
                            "record": "trial",
                            "rate_pps_per_pair": rate,
                            "trial": i,
                            "valid": ok,
                            "probers_valid": all(p.get("valid") for p in ps),
                            "max_late_ms": round(late / 1e6, 3),
                            "p99_late_ms": max(p.get("p99_late_ns_bucket", 0) for p in ps) / 1e6,
                            "late_over_tolerance": sum(p.get("late_over_tolerance", 0) for p in ps),
                            "sent": sum(p.get("sent", 0) for p in ps),
                            "tracer_lost": ts.get("ringbuf_lost"),
                            "cpu_util": round(cpu, 4),
                        }
                    )
                    typer.echo(
                        f"{rate} #{i}: valid={ok} max_late {late / 1e6:.2f} ms cpu {cpu:.2f}"
                    )
                    for f in SCRATCH.glob("*.jsonl"):
                        f.unlink()
                w.write(
                    {
                        "record": "summary",
                        "rate_pps_per_pair": rate,
                        "trials": trials,
                        "valid": valid,
                        "max_late_ms": summarize(lates),
                    }
                )
    finally:
        labmod.down(lab)


if __name__ == "__main__":
    typer.run(main)
