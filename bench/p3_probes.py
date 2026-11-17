"""Phase 3 acceptance: probes run clean at the target rate on a steady lab.

T1 eBGP, every host probes every other host at RATE pps per pair for DURATION
seconds while a recorder runs on every router. Clean means: every prober's
schedule stayed within tolerance, every sent probe was received exactly once,
and the recorders saw no FIB change and no overrun (the network is steady).

Output: results/p3/probes_clean.jsonl (machine record, per-trial and per-pair
records) and the raw probes.jsonl.gz / fib_events.jsonl.gz per trial.
"""

from __future__ import annotations

import gzip
import json
import shutil
from collections import Counter
from pathlib import Path

import typer

from bench.common import RESULTS, cpu_sample, cpu_util
from labctl import lab as labmod
from labctl.procs import (
    build_go,
    merge_fib_events,
    start_probers,
    start_recorders,
    stop_recorders,
    wait_probers,
)
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode


def gz(path: Path) -> Path:
    out = path.with_suffix(path.suffix + ".gz")
    with path.open("rb") as a, gzip.open(out, "wb", compresslevel=6) as b:
        shutil.copyfileobj(a, b)
    path.unlink()
    return out


def main(
    rate: int = 1000, duration: float = 10.0, trials: int = 3, out_dir: Path = RESULTS / "p3"
) -> None:
    build_go()
    lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
    labmod.up(lab)
    res, _, _ = verify_wait(lab, 120)
    if not res.ok:
        raise SystemExit(f"lab did not verify: {res.failures}")
    names = {h.site: h.name for h in lab.plan.hosts}
    all_clean = True
    with ResultWriter(out_dir / "probes_clean.jsonl") as w:
        for trial in range(trials):
            tdir = out_dir / f"trial{trial}"
            recs = start_recorders(lab, tdir)
            c0 = cpu_sample()
            pr = start_probers(lab, rate, duration)
            pstats = wait_probers(lab, pr, tdir / "probes.jsonl", timeout_s=duration + 30)
            cpu = cpu_util(c0, cpu_sample())
            rstats = stop_recorders(recs)
            merge_fib_events(recs, tdir / "fib_events.jsonl")
            for r in recs:
                r.out.unlink()

            sent, recv, dup = Counter(), Counter(), 0
            seen = set()
            fib_changes = 0
            with (tdir / "probes.jsonl").open() as f:
                for line in f:
                    x = json.loads(line)
                    if x.get("k") == "s":
                        sent[(x["src"], x["dst"])] += 1
                    elif x.get("k") == "r":
                        key = (x["src"], x["dst"], x["seq"])
                        if key in seen:
                            dup += 1
                        seen.add(key)
                        recv[(x["src"], x["dst"])] += 1
            with (tdir / "fib_events.jsonl").open() as f:
                fib_changes = sum(1 for line in f if json.loads(line).get("kind") == "fib")
            gz(tdir / "probes.jsonl")
            gz(tdir / "fib_events.jsonl")

            for (s, d), n in sorted(sent.items()):
                w.write(
                    {
                        "record": "pair",
                        "trial": trial,
                        "src": names[s],
                        "dst": names[d],
                        "sent": n,
                        "received": recv[(s, d)],
                        "lost": n - recv[(s, d)],
                    }
                )
            lost = sum(sent.values()) - sum(recv.values())
            probers_valid = all(p.get("valid") for p in pstats)
            rec_valid = all(r.get("valid") for r in rstats)
            clean = probers_valid and rec_valid and lost == 0 and dup == 0 and fib_changes == 0
            all_clean &= clean
            w.write(
                {
                    "record": "trial",
                    "trial": trial,
                    "rate_pps_per_pair": rate,
                    "duration_s": duration,
                    "pairs": len(sent),
                    "sent": sum(sent.values()),
                    "received": sum(recv.values()),
                    "lost": lost,
                    "duplicates": dup,
                    "fib_changes": fib_changes,
                    "max_late_ns": max(p.get("max_late_ns", 0) for p in pstats),
                    "probers_valid": probers_valid,
                    "recorders_valid": rec_valid,
                    "cpu_util": round(cpu, 3),
                    "clean": clean,
                    "prober_stats": pstats,
                    "recorder_stats": rstats,
                }
            )
            typer.echo(
                f"trial {trial}: sent {sum(sent.values())} lost {lost} dup {dup} "
                f"fib {fib_changes} max_late "
                f"{max(p.get('max_late_ns', 0) for p in pstats) / 1e6:.2f} ms "
                f"probers_valid={probers_valid} recorders_valid={rec_valid} cpu={cpu:.2f}"
            )
    labmod.down(lab)
    if not all_clean:
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
