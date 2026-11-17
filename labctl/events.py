"""Fault catalog (SPEC 6). Each event has an action and an undo.

carrier_down  `ip link set <if> down` on one end; the veth peer loses carrier.
silent_down   netem 100% loss on one end's egress: one direction fails
              silently, so detection relies on BFD or protocol timers.
link_up       restore a link that was taken down before the run (recovery).
node_down     freeze every FRR process on a router (SIGSTOP, watchfrr
              included, ADR-014): routing stops, interfaces stay up, the
              kernel keeps forwarding with its last FIB.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from labctl.lab import Lab, run, sudo_prefix

EVENTS = ("carrier_down", "silent_down", "link_up", "node_down")
FRR_PROCS = {"watchfrr", "zebra", "mgmtd", "staticd", "bgpd", "ospfd", "isisd", "bfdd"}


@dataclass
class Location:
    kind: str  # "link" or "node"
    node: str  # the end acted on (link) or the router (node)
    iface: str = ""
    peer: str = ""
    peer_iface: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def fabric_links(lab: Lab) -> list[tuple[str, str, str, str]]:
    routers = {r.name for r in lab.plan.routers}
    return [
        (lk.a, lk.a_iface, lk.b, lk.b_iface)
        for lk in lab.plan.links
        if lk.a in routers and lk.b in routers
    ]


def choose_location(lab: Lab, event: str, seed: int, spec: str | None = None) -> Location:
    """Seeded choice. spec "a-b" picks the link a-b acted on at a; "r" picks a router."""
    rng = random.Random(seed)
    if event == "node_down":
        names = sorted(r.name for r in lab.plan.routers)
        node = spec if spec else rng.choice(names)
        if node not in names:
            raise ValueError(f"unknown router {node}")
        return Location("node", node)
    links = fabric_links(lab)
    if spec:
        a, b = spec.split("-")
        for la, ai, lb, bi in links:
            if (la, lb) == (a, b):
                return Location("link", la, ai, lb, bi)
            if (la, lb) == (b, a):
                return Location("link", lb, bi, la, ai)
        raise ValueError(f"no fabric link {spec}")
    la, ai, lb, bi = rng.choice(links)
    if rng.random() < 0.5:
        return Location("link", la, ai, lb, bi)
    return Location("link", lb, bi, la, ai)


def frr_pids(lab: Lab, node: str) -> list[int]:
    out = run(["docker", "top", lab.container(node), "-eo", "pid,comm"]).stdout
    pids = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] in FRR_PROCS:
            pids.append(int(parts[0]))
    return pids


@dataclass
class Event:
    name: str
    loc: Location
    act: Callable[[], None]
    undo: Callable[[], None]
    prepare: Callable[[], None] = field(default=lambda: None)


def make_event(lab: Lab, name: str, loc: Location) -> Event:
    def ip(*args: str) -> Callable[[], None]:
        return lambda: lab.netns_exec(loc.node, "ip", *args)

    if name == "carrier_down":
        return Event(
            name, loc, ip("link", "set", loc.iface, "down"), ip("link", "set", loc.iface, "up")
        )
    if name == "silent_down":
        return Event(
            name,
            loc,
            lambda: lab.netns_exec(
                loc.node, "tc", "qdisc", "add", "dev", loc.iface, "root", "netem", "loss", "100%"
            ),
            lambda: lab.netns_exec(loc.node, "tc", "qdisc", "del", "dev", loc.iface, "root"),
        )
    if name == "link_up":
        return Event(
            name,
            loc,
            ip("link", "set", loc.iface, "up"),
            lambda: None,
            prepare=ip("link", "set", loc.iface, "down"),
        )
    if name == "node_down":

        def signal(sig: str) -> Callable[[], None]:
            def f() -> None:
                pids = frr_pids(lab, loc.node)
                if not pids:
                    raise RuntimeError(f"no FRR processes on {loc.node}")
                run([*sudo_prefix(), "kill", f"-{sig}", *map(str, pids)])

            return f

        return Event(name, loc, signal("STOP"), signal("CONT"))
    raise ValueError(f"unknown event {name}")


def fib_digest(lab: Lab) -> str:
    """All routers' kernel routes and nexthop objects, for quiet-period checks."""
    parts = []
    for r in lab.plan.routers:
        routes = lab.netns_exec(r.name, "ip", "-j", "route", "show", "table", "main").stdout
        nhs = lab.netns_exec(r.name, "ip", "-j", "nexthop", "show").stdout
        parts.append(json.dumps([r.name, json.loads(routes or "[]"), json.loads(nhs or "[]")]))
    return "\n".join(parts)


def wait_fib_quiet(lab: Lab, quiet_s: float = 2.0, timeout_s: float = 90.0) -> float:
    """Wait until no router's FIB changed for quiet_s; return seconds waited."""
    t0 = time.monotonic()
    last = fib_digest(lab)
    since = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        time.sleep(0.5)
        now = fib_digest(lab)
        if now != last:
            last, since = now, time.monotonic()
        elif time.monotonic() - since >= quiet_s:
            return time.monotonic() - t0
    raise TimeoutError(f"FIB not quiet for {quiet_s}s within {timeout_s}s")
