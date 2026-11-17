"""`labctl snapshot`: every router's kernel routes and nexthop objects, stamped
with CLOCK_MONOTONIC nanoseconds. Snapshots are the starting state for replay."""

from __future__ import annotations

import json
import time
from pathlib import Path

from labctl.lab import Lab
from labctl.machine import machine_record


def snapshot_router(lab: Lab, node: str) -> dict:
    t0 = time.monotonic_ns()
    routes = json.loads(lab.netns_exec(node, "ip", "-j", "route", "show", "table", "main").stdout
                        or "[]")
    nexthops = json.loads(lab.netns_exec(node, "ip", "-j", "nexthop", "show").stdout or "[]")
    t1 = time.monotonic_ns()
    return {"t_start_ns": t0, "t_end_ns": t1, "routes": routes, "nexthops": nexthops}


def snapshot(lab: Lab) -> dict:
    return {
        "machine": machine_record(),
        "lab": lab.name,
        "clock": "CLOCK_MONOTONIC",
        "routers": {r.name: snapshot_router(lab, r.name) for r in lab.plan.routers},
    }


def write_snapshot(lab: Lab, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot(lab), indent=1, sort_keys=True) + "\n")
    return path
