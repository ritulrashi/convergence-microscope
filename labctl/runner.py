"""`labctl run`: one seeded fault-injection run (SPEC 6).

Order: verify the lab, prepare the event (link_up takes the link down and
waits for the FIB to go quiet), start recorders on every router and the
tracer, start probers on every host with a shared CLOCK_MONOTONIC start,
fire the event at start + event_at, wait for the probes, stop everything,
undo the event and wait until verify passes again. Then replay and report.

run.json holds topology, mode, timers, event, location, seed, event time and
validity flags. A run is invalid, and kept, if a prober slipped its
schedule, a recorder overran or missed messages, or the tracer lost events.
"""

from __future__ import annotations

import gzip
import json
import shutil
import time
from pathlib import Path

from bench.common import cpu_sample, cpu_util, loadavg1
from labctl.events import choose_location, make_event, wait_fib_quiet
from labctl.lab import Lab, run
from labctl.procs import (
    BUILD,
    merge_fib_events,
    start_probers,
    start_recorders,
    start_tracer,
    stop_recorders,
    stop_tracer,
    wait_probers,
)
from labctl.report import write_report
from labctl.verify import verify_wait
from labgen.render import REPO


def _jsonl_rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def gzip_file(path: Path) -> None:
    with path.open("rb") as a, gzip.open(str(path) + ".gz", "wb", compresslevel=6) as b:
        shutil.copyfileobj(a, b)
    path.unlink()


def do_run(
    lab: Lab,
    event: str,
    seed: int,
    out_root: Path,
    location: str | None = None,
    rate: int = 1000,
    duration_s: float = 8.0,
    event_at_s: float = 2.0,
    tracer: bool = True,
    keep_raw: bool = False,
    tag: str = "",
    restore_timeout_s: float = 180.0,
) -> dict:
    loc = choose_location(lab, event, seed, location)
    ev = make_event(lab, event, loc)
    loc_str = loc.node if loc.kind == "node" else f"{loc.node}:{loc.iface}-{loc.peer}"
    run_id = f"{lab.name.removeprefix('cm-')}-{event}-s{seed}{tag}"
    d = out_root / run_id
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    shutil.copy(lab.dir / "plan.json", d / "plan.json")

    res, _, _ = verify_wait(lab, 120)
    if not res.ok:
        raise RuntimeError(f"lab does not verify before the run: {res.failures[:3]}")
    invalid: list[str] = []
    ev.prepare()
    if event == "link_up":
        wait_fib_quiet(lab, quiet_s=3.0)

    recs = start_recorders(lab, d / "rec")
    tr = start_tracer(lab, d / "hops.jsonl") if tracer else None
    c0 = cpu_sample()
    pr = start_probers(lab, rate, duration_s, lead_s=1.0)
    t_fire = pr.start_ns + int(event_at_s * 1e9)
    while (now := time.monotonic_ns()) < t_fire:
        time.sleep(min(0.05, (t_fire - now) / 1e9))
    t_ev0 = time.monotonic_ns()
    ev.act()
    t_ev1 = time.monotonic_ns()
    pstats = wait_probers(lab, pr, d / "probes.jsonl", timeout_s=duration_s + 60)
    cpu = cpu_util(c0, cpu_sample())
    load = loadavg1()
    rstats = stop_recorders(recs)
    tstats = stop_tracer(tr) if tr else None
    merge_fib_events(recs, d / "fib_events.jsonl")
    shutil.rmtree(d / "rec")

    # The command's own latency (sudo, nsenter) sits between t_ev0 and the
    # change taking effect. For link events the recorder saw the kernel's
    # link change: that is the event time. Otherwise the command's end bounds it.
    t_event, t_source = t_ev1, "event command end"
    if event in ("carrier_down", "link_up"):
        for e in _jsonl_rows(d / "fib_events.jsonl"):
            if (
                e.get("kind") == "link"
                and e.get("router") == loc.node
                and e.get("ifname") == loc.iface
                and e["t"] >= t_ev0
            ):
                t_event, t_source = e["t"], "recorder link event"
                break

    ev.undo()
    res2, restore_s, _ = verify_wait(lab, restore_timeout_s)
    if not res2.ok:
        invalid.append(f"lab did not verify after undo within {restore_timeout_s}s")

    for p in pstats:
        if not p.get("valid"):
            invalid.append(f"prober {p.get('host')}: {p.get('invalid_reason')}")
    for r in rstats:
        if not r.get("valid"):
            invalid.append(f"recorder {r.get('router')}: {r.get('invalid_reason')}")
    if tstats is not None and not tstats.get("valid"):
        invalid.append(f"tracer: {tstats.get('invalid_reason')}")

    info = {
        "run_id": run_id,
        "topology": lab.plan.topology,
        "mode": lab.plan.mode,
        "bfd": lab.plan.bfd,
        "timers": {r.name: r.timers for r in lab.plan.routers},
        "event": event,
        "location": loc_str,
        "location_detail": loc.to_dict(),
        "seed": seed,
        "rate_pps_per_pair": rate,
        "probe_start_ns": pr.start_ns,
        "probe_end_ns": pr.start_ns + int(duration_s * 1e9),
        "event_t_ns": t_event,
        "event_time_source": t_source,
        "event_cmd_start_ns": t_ev0,
        "event_cmd_ns": t_ev1 - t_ev0,
        "tracer": tracer,
        "cpu_util": round(cpu, 4),
        "loadavg1": load,
        "restore_verify_s": round(restore_s, 3) if res2.ok else None,
        "prober_stats": pstats,
        "recorder_stats": rstats,
        "tracer_stats": tstats,
        "valid": not invalid,
        "invalid_reasons": invalid,
    }
    (d / "run.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")

    run(
        [
            str(BUILD / "replay"),
            "-run",
            str(d),
            "-reasons",
            str(REPO / "results" / "calibration" / "drop_reasons.json"),
        ],
        timeout=600,
    )
    rep = write_report(d)
    for name in ("probes.jsonl", "hops.jsonl"):
        p = d / name
        if p.exists():
            if keep_raw:
                gzip_file(p)
            else:
                p.unlink()
    gzip_file(d / "fib_events.jsonl")
    return rep
