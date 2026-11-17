"""verify checks against FRR JSON captured from a running T1 eBGP lab."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

from labctl.verify import check_peers, check_rib, expected_ecmp, expected_prefixes, ping_pairs
from labgen.ipam import build_plan
from labgen.model import Intent, Mode

REPO = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures" / "frr"


def plan_t1():
    d = yaml.safe_load((REPO / "intent/t1-leafspine.yaml").read_text())
    return build_plan(Intent.model_validate(d), Mode.ebgp)


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text())


def test_captured_leaf1_passes() -> None:
    plan = plan_t1()
    leaf1 = plan.router("leaf1")
    assert check_peers(plan, leaf1, load("t1_ebgp_leaf1_bgp_summary.json")) == []
    assert check_rib(plan, leaf1, load("t1_ebgp_leaf1_ip_route.json")) == []


def test_peer_down_is_reported() -> None:
    plan = plan_t1()
    data = load("t1_ebgp_leaf1_bgp_summary.json")
    data["ipv4Unicast"]["peers"]["10.1.0.3"]["state"] = "Active"
    assert check_peers(plan, plan.router("leaf1"), data) == [
        "leaf1: ebgp peer spine2 (10.1.0.3) is Active"
    ]


def test_missing_prefix_and_ecmp_width() -> None:
    plan = plan_t1()
    routes = load("t1_ebgp_leaf1_ip_route.json")
    broken = copy.deepcopy(routes)
    del broken["10.10.3.0/24"]
    broken["10.0.0.4/32"][0]["nexthops"][1]["fib"] = False
    fails = check_rib(plan, plan.router("leaf1"), broken)
    assert "leaf1: no selected route for 10.10.3.0/24" in fails
    assert "leaf1: ECMP width for 10.0.0.4/32 is 1, expected 2" in fails


def test_expectations() -> None:
    plan = plan_t1()
    assert expected_ecmp(plan, plan.router("leaf1"))["10.10.4.0/24"] == 2
    assert expected_ecmp(plan, plan.router("spine1")) == {}
    assert "10.0.0.2/32" not in expected_prefixes(plan, plan.router("spine1"))
    assert "10.0.0.2/32" in expected_prefixes(plan, plan.router("leaf1"))
    assert len(ping_pairs(plan)) == 12
