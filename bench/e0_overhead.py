"""E0: instrument overhead and lag (10 trials per setting).

A. Max probe rate with zero tracer loss. T1 eBGP, all 12 host pairs, 5 s per
   trial, tracer on (writing its normal JSONL to a scratch file), probers
   logging stats only. Rates per pair: 1000, 2000, 4000, 8000 pps.
B. Probe-path CPU cost, tracer on vs off. 1000 pps per pair, 10 s, trials
   interleaved on/off. Whole-VM CPU utilisation from /proc/stat, and, with
   kernel.bpf_stats_enabled=1, the eBPF programs' own run time per call.
C. Recorder receipt lag. In a daemon-free namespace, 50 route add/delete
   operations 20 ms apart while the recorder and lagprobe (kprobes on
   rtnl_notify, fib_table_insert, fib_table_delete) run. Lag = recorder
   receipt time minus the kernel call time. Idle, and with the T1 lab under
   1000 pps all-pairs probing with tracer and recorders on.

Output: results/e0/e0.jsonl.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import typer

from bench.calib_recorder import NS, setup_ns, start_ns_recorder, teardown_ns
from bench.common import RESULTS, cpu_sample, cpu_util, summarize
from labctl import lab as labmod
from labctl.lab import run, sudo_prefix
from labctl.procs import (
    BUILD,
    Recorder,
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

SCRATCH = Path("/tmp/cm-e0")


def bpf_prog_stats() -> dict[str, dict]:
    out = run([*sudo_prefix(), "bpftool", "prog", "show", "-j"]).stdout
    return {
        p["name"]: {"run_time_ns": p.get("run_time_ns", 0), "run_cnt": p.get("run_cnt", 0)}
        for p in json.loads(out)
        if p.get("name") in ("tp_rx", "tp_drop")
    }


def probe_round(lab, rate: int, dur: float, tracer: bool) -> dict:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    tr = start_tracer(lab, SCRATCH / "hops.jsonl") if tracer else None
    before = bpf_prog_stats() if tracer else {}
    c0 = cpu_sample()
    pr = start_probers(lab, rate, dur, packets=False, grace_s=1.0)
    pstats = wait_probers(lab, pr, SCRATCH / "probes.jsonl", timeout_s=dur + 30)
    cpu = cpu_util(c0, cpu_sample())
    after = bpf_prog_stats() if tracer else {}
    tstats = stop_tracer(tr) if tr else None
    sent = sum(p.get("sent", 0) for p in pstats)
    recv = sum(p.get("recv", 0) for p in pstats)
    rec = {
        "rate_pps_per_pair": rate,
        "duration_s": dur,
        "tracer": tracer,
        "sent": sent,
        "received": recv,
        "lost": sent - recv,
        "probers_valid": all(p.get("valid") for p in pstats),
        "max_late_ns": max(p.get("max_late_ns", 0) for p in pstats),
        "cpu_util": round(cpu, 4),
    }
    if tstats is not None:
        rec["tracer_ringbuf_lost"] = tstats.get("ringbuf_lost")
        rec["tracer_events"] = tstats.get("events_written")
        rec["tracer_valid"] = tstats.get("valid")
        for name in ("tp_rx", "tp_drop"):
            b, a = before.get(name, {}), after.get(name, {})
            cnt = a.get("run_cnt", 0) - b.get("run_cnt", 0)
            ns = a.get("run_time_ns", 0) - b.get("run_time_ns", 0)
            rec[f"{name}_calls"] = cnt
            rec[f"{name}_ns_per_call"] = round(ns / cnt, 1) if cnt else None
        (SCRATCH / "hops.jsonl").unlink(missing_ok=True)
    return rec


def lag_trial(changes: int = 50, gap_s: float = 0.02) -> dict:
    work = SCRATCH / "lag"
    work.mkdir(parents=True, exist_ok=True)
    setup_ns()
    rec = start_ns_recorder(work)
    ready = work / ".ready_lag"
    ready.unlink(missing_ok=True)
    lp = subprocess.Popen(
        [
            *sudo_prefix(),
            str(BUILD / "lagprobe"),
            "-netns",
            f"/run/netns/{NS}",
            "-out",
            str(work / "lag.jsonl"),
            "-ready",
            str(ready),
        ],
        stderr=subprocess.PIPE,
        text=True,
    )
    while not ready.exists():
        if lp.poll() is not None:
            raise RuntimeError(lp.stderr.read())
        time.sleep(0.05)
    try:
        for i in range(changes):
            pfx = f"192.0.2.{i % 25 + 1}/32"
            verb = "add" if (i // 25) % 2 == 0 else "del"
            args = ["route", verb, pfx] + (
                ["via", "10.99.1.2", "dev", "d1"] if verb == "add" else []
            )
            run([*sudo_prefix(), "ip", "-n", NS, *args])
            time.sleep(gap_s)
        time.sleep(0.3)
    finally:
        rstats = stop_recorders([Recorder("calib", work / "fib_calib.jsonl", rec)])
        lp.send_signal(15)
        lp.wait(timeout=10)
        teardown_ns()
    calls = [json.loads(x) for x in (work / "lag.jsonl").read_text().splitlines() if x.strip()]
    start = next(c for c in calls if c["kind"] == "start")
    lstats = next((c for c in calls if c["kind"] == "stats"), {"valid": False})
    notify = sorted(c["t"] for c in calls if c.get("fn") == "rtnl_notify" and c.get("group") == 7)
    fibfn = sorted(c["t"] for c in calls if c.get("fn") in ("fib_table_insert", "fib_table_delete"))
    events = [
        json.loads(x)
        for x in (work / "fib_calib.jsonl").read_text().splitlines()
        if '"kind":"fib"' in x and "192.0.2." in x
    ]
    lag_n, lag_f = [], []
    for e in events:
        t = e["t"]
        n = [x for x in notify if x <= t]
        f = [x for x in fibfn if x <= t]
        if n:
            lag_n.append(t - n[-1])
        if f:
            lag_f.append(t - f[-1])
    return {
        "changes": changes,
        "fib_events": len(events),
        "kprobes_attached": start["attached"],
        "lag_vs_rtnl_notify_ns": summarize([float(x) for x in lag_n]),
        "lag_vs_fib_table_ns": summarize([float(x) for x in lag_f]),
        "lag_vs_rtnl_notify_all_ns": lag_n,
        "recorder_valid": rstats[0].get("valid"),
        "lagprobe_valid": lstats.get("valid"),
    }


def main(
    trials: int = 10, out: Path = RESULTS / "e0" / "e0.jsonl", rates: str = "1000,2000,4000,8000"
) -> None:
    build_go()
    run([*sudo_prefix(), "sysctl", "-w", "kernel.bpf_stats_enabled=1"])
    with ResultWriter(out) as w:
        # C (idle) first, before any lab exists.
        idle = []
        for i in range(trials):
            r = lag_trial()
            idle.append(r)
            w.write({"record": "trial", "part": "C", "load": "idle", "trial": i, **r})
            typer.echo(f"C idle #{i}: notify lag p50 {r['lag_vs_rtnl_notify_ns']['median']}")

        lab = labmod.load(Path("intent/t1-leafspine.yaml"), Mode.ebgp, False)
        labmod.up(lab)
        try:
            res, _, _ = verify_wait(lab, 120)
            if not res.ok:
                raise SystemExit(f"lab did not verify: {res.failures}")
            # A
            for rate in [int(x) for x in rates.split(",")]:
                for i in range(trials):
                    r = probe_round(lab, rate, 5.0, tracer=True)
                    w.write({"record": "trial", "part": "A", "trial": i, **r})
                    typer.echo(
                        f"A {rate} #{i}: lost {r['tracer_ringbuf_lost']} "
                        f"probers_valid {r['probers_valid']} cpu {r['cpu_util']}"
                    )
            # B
            for i in range(trials):
                for tracer in (False, True):
                    r = probe_round(lab, 1000, 10.0, tracer=tracer)
                    w.write({"record": "trial", "part": "B", "trial": i, **r})
                    typer.echo(f"B tracer={tracer} #{i}: cpu {r['cpu_util']}")
            # C (loaded): probes, tracer and recorders on while the lag trial runs.
            for i in range(trials):
                tr = start_tracer(lab, SCRATCH / "hops_c.jsonl")
                recs = start_recorders(lab, SCRATCH / "recs_c")
                pr = start_probers(lab, 1000, 6.0, packets=False, grace_s=0.5)
                time.sleep(1.5)  # probes are flowing before the changes start
                result = lag_trial()
                pstats = wait_probers(lab, pr, SCRATCH / "probes_c.jsonl", timeout_s=40)
                stop_recorders(recs)
                stop_tracer(tr)
                w.write(
                    {
                        "record": "trial",
                        "part": "C",
                        "load": "probes+tracer+recorders",
                        "trial": i,
                        "probers_valid": all(p.get("valid") for p in pstats),
                        **result,
                    }
                )
                typer.echo(
                    f"C loaded #{i}: notify lag p50 {result['lag_vs_rtnl_notify_ns']['median']}"
                )
        finally:
            labmod.down(lab)
    typer.echo(f"wrote {out}")


if __name__ == "__main__":
    typer.run(main)
