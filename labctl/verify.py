"""`labctl verify`: is the lab what the plan says it should be?

Checks use FRR JSON output only. Each check is a pure function from the plan
plus parsed JSON to a list of failure strings, so they are unit-tested on
captured output without a running lab.
"""

from __future__ import annotations

import itertools
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from labctl.lab import Lab
from labgen.ipam import Plan, RouterPlan

# --- expectations -----------------------------------------------------------


def expected_peers(plan: Plan, r: RouterPlan) -> dict[str, str]:
    """Return {key: peer name}. The key is what FRR reports per mode:
    neighbor address (BGP), neighbor router ID (OSPF), neighbor hostname (IS-IS)."""
    out: dict[str, str] = {}
    for i in r.ifaces:
        if i.kind != "fabric":
            continue
        if plan.mode == "ebgp":
            out[i.peer_address] = i.peer
        elif plan.mode == "ospf":
            out[plan.router(i.peer).router_id] = i.peer
        else:
            out[i.peer] = i.peer
    return out


def expected_prefixes(plan: Plan, r: RouterPlan | None = None) -> set[str]:
    """Prefixes R must have. In leafspine eBGP, spines share one ASN and leaves
    never re-export, so a spine never learns another spine's loopback. That is
    the RFC 7938 design, not a fault."""
    out = {x.loopback for x in plan.routers}
    for x in plan.routers:
        out.update(x.host_subnets)
    if r is not None and plan.mode == "ebgp" and plan.topology == "leafspine" and r.role == "spine":
        out -= {x.loopback for x in plan.routers if x.role == "spine" and x.name != r.name}
    return out


def expected_ecmp(plan: Plan, r: RouterPlan) -> dict[str, int]:
    """T1 only: a leaf reaches every other leaf's prefixes over every spine."""
    if plan.topology != "leafspine" or r.role != "leaf":
        return {}
    spines = sum(1 for x in plan.routers if x.role == "spine")
    out: dict[str, int] = {}
    for other in plan.routers:
        if other.role == "leaf" and other.name != r.name:
            out[other.loopback] = spines
            for s in other.host_subnets:
                out[s] = spines
    return out


# --- parsers / checks ---------------------------------------------------------


def peer_states(mode: str, data: dict) -> dict[str, str]:
    """Normalise FRR neighbor JSON to {key: state}."""
    states: dict[str, str] = {}
    if mode == "ebgp":
        peers = data.get("ipv4Unicast", {}).get("peers", {})
        for addr, p in peers.items():
            states[addr] = p.get("state", "?")
    elif mode == "ospf":
        for rid, lst in data.get("neighbors", {}).items():
            for n in lst if isinstance(lst, list) else [lst]:
                st = n.get("nbrState") or n.get("converged") or "?"
                states[rid] = st.split("/")[0]
    else:
        for area in data.get("areas", []):
            for c in area.get("circuits", []):
                adj = c.get("adj")
                if adj is None:
                    continue
                st = c.get("interface", {}).get("state") or c.get("state") or "?"
                states[adj] = st
    return states


UP_STATE = {"ebgp": "Established", "ospf": "Full", "isis": "Up"}


def check_peers(plan: Plan, r: RouterPlan, data: dict) -> list[str]:
    states = peer_states(plan.mode, data)
    want = UP_STATE[plan.mode]
    fails = []
    for key, peer in sorted(expected_peers(plan, r).items()):
        st = states.get(key)
        if st != want:
            fails.append(f"{r.name}: {plan.mode} peer {peer} ({key}) is {st or 'missing'}")
    return fails


def fib_nexthops(entry: dict) -> int:
    return sum(1 for nh in entry.get("nexthops", []) if nh.get("fib"))


def check_rib(plan: Plan, r: RouterPlan, routes: dict) -> list[str]:
    fails = []
    for pfx in sorted(expected_prefixes(plan, r)):
        entries = routes.get(pfx, [])
        sel = [e for e in entries if e.get("selected")]
        if not sel:
            fails.append(f"{r.name}: no selected route for {pfx}")
            continue
        if not any(e.get("installed") for e in sel) and sel[0].get("protocol") != "connected":
            fails.append(f"{r.name}: route {pfx} selected but not installed")
    for pfx, width in sorted(expected_ecmp(plan, r).items()):
        sel = [e for e in routes.get(pfx, []) if e.get("selected")]
        got = fib_nexthops(sel[0]) if sel else 0
        if got != width:
            fails.append(f"{r.name}: ECMP width for {pfx} is {got}, expected {width}")
    return fails


def ping_pairs(plan: Plan) -> list[tuple[str, str, str]]:
    addr = {h.name: h.address.split("/")[0] for h in plan.hosts}
    return [(a, b, addr[b]) for a, b in itertools.permutations(sorted(addr), 2)]


# --- driver ------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool
    failures: list[str] = field(default_factory=list)
    checks: dict[str, int] = field(default_factory=dict)


PEER_CMD = {
    "ebgp": "show bgp summary json",
    "ospf": "show ip ospf neighbor json",
    "isis": "show isis neighbor json",
}


def verify_once(lab: Lab, ping: bool = True) -> VerifyResult:
    plan = lab.plan
    failures: list[str] = []
    counts = {"peers": 0, "rib": 0, "ping": 0}

    def per_router(r: RouterPlan) -> list[str]:
        f = check_peers(plan, r, lab.vtysh_json(r.name, PEER_CMD[plan.mode]))
        f += check_rib(plan, r, lab.vtysh_json(r.name, "show ip route json"))
        return f

    with ThreadPoolExecutor(max_workers=4) as ex:
        for f in ex.map(per_router, plan.routers):
            failures += f
    counts["peers"] = sum(len(expected_peers(plan, r)) for r in plan.routers)
    counts["rib"] = sum(len(expected_prefixes(plan, r)) for r in plan.routers)

    if ping and not failures:
        def one(p: tuple[str, str, str]) -> str | None:
            a, b, ip = p
            res = lab.exec(a, "ping", "-c", "2", "-i", "0.2", "-W", "1", ip, check=False)
            return None if res.returncode == 0 else f"ping {a} -> {b} ({ip}) failed"

        pairs = ping_pairs(plan)
        counts["ping"] = len(pairs)
        with ThreadPoolExecutor(max_workers=4) as ex:
            failures += [f for f in ex.map(one, pairs) if f]
    elif ping:
        failures.append("ping skipped: control-plane checks failed")
    return VerifyResult(not failures, failures, counts)


def verify_wait(lab: Lab, timeout_s: float, interval_s: float = 1.0
                ) -> tuple[VerifyResult, float, int]:
    """Repeat verify until it passes or times out.
    Return (last result, seconds from start to the passing attempt's start, attempts)."""
    t0 = time.monotonic()
    attempts = 0
    while True:
        attempts += 1
        start = time.monotonic()
        try:
            res = verify_once(lab)
        except Exception as e:  # container not ready, vtysh not up yet, bad JSON
            res = VerifyResult(False, [f"verify error: {e}"])
        if res.ok or time.monotonic() - t0 > timeout_s:
            return res, start - t0, attempts
        time.sleep(interval_s)
