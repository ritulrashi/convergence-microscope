"""Generator: golden files, determinism, and one failing input per validation rule."""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from labgen.ipam import PoolExhausted, build_plan
from labgen.model import Intent, Mode
from labgen.render import render

REPO = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).parent / "golden"
INTENTS = {"t1": REPO / "intent/t1-leafspine.yaml", "t2": REPO / "intent/t2-mesh.yaml"}
FRR = "quay.io/frrouting/frr:TEST"
PAIRS = [(t, m) for t in INTENTS for m in Mode]


def intent_data(topo: str) -> dict:
    return yaml.safe_load(INTENTS[topo].read_text())


def rendered(topo: str, mode: Mode) -> dict[str, str]:
    return render(build_plan(Intent.model_validate(intent_data(topo)), mode), FRR)


@pytest.mark.parametrize(("topo", "mode"), PAIRS, ids=[f"{t}-{m.value}" for t, m in PAIRS])
def test_golden(topo: str, mode: Mode) -> None:
    files = rendered(topo, mode)
    gdir = GOLDEN / f"{topo}-{mode.value}"
    if os.environ.get("UPDATE_GOLDEN"):
        for rel, content in files.items():
            p = gdir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content.encode())
    on_disk = {p.relative_to(gdir).as_posix() for p in gdir.rglob("*") if p.is_file()}
    assert on_disk == set(files), "golden file set differs; rerun with UPDATE_GOLDEN=1"
    for rel, content in files.items():
        assert (gdir / rel).read_bytes().decode() == content, f"{topo}-{mode.value}/{rel}"


@pytest.mark.parametrize(("topo", "mode"), PAIRS, ids=[f"{t}-{m.value}" for t, m in PAIRS])
def test_deterministic(topo: str, mode: Mode) -> None:
    assert rendered(topo, mode) == rendered(topo, mode)


def test_t1_shape() -> None:
    plan = build_plan(Intent.model_validate(intent_data("t1")))
    assert len([lk for lk in plan.links if not lk.b.startswith("h")]) == 8
    assert {r.asn for r in plan.routers if r.role == "spine"} == {65000}
    assert len({r.asn for r in plan.routers if r.role == "leaf"}) == 4
    assert plan.router("leaf1").host_subnets == ["10.10.1.0/24"]
    assert plan.router("spine1").loopback == "10.0.0.1/32"


def test_leaf_exports_only_local_prefixes() -> None:
    conf = rendered("t1", Mode.ebgp)["leaf1/frr.conf"]
    assert "match ip address prefix-list LOCAL" in conf
    assert "match ip address" not in rendered("t1", Mode.ebgp)["spine1/frr.conf"]


def test_per_router_timer_override() -> None:
    d = intent_data("t2")
    d["nodes"][2]["timers"] = {"spf_delay_ms": 900}
    conf = render(build_plan(Intent.model_validate(d)), FRR)["r3/frr.conf"]
    assert "timers throttle spf 900 200 5000" in conf
    other = render(build_plan(Intent.model_validate(d)), FRR)["r2/frr.conf"]
    assert "timers throttle spf 50 200 5000" in other


# --- validation: one failing input per rule ---------------------------------


def bad(topo: str, mutate) -> str:
    d = copy.deepcopy(intent_data(topo))
    mutate(d)
    with pytest.raises((ValidationError, PoolExhausted)) as ei:
        build_plan(Intent.model_validate(d))
    return str(ei.value)


def test_rejects_duplicate_asn() -> None:
    def m(d):
        d["routing"]["mode"] = "ebgp"
        d["nodes"][1]["asn"] = 65001  # r1 gets base 65001
    assert "duplicate ASN 65001" in bad("t2", m)


def test_rejects_duplicate_router_id() -> None:
    def m(d):
        d["nodes"][0]["router_id"] = "1.1.1.1"
        d["nodes"][1]["router_id"] = "1.1.1.1"
    assert "duplicate router ID 1.1.1.1" in bad("t2", m)


def test_rejects_overlapping_pools() -> None:
    def m(d):
        d["pools"]["link"] = "10.0.0.0/16"
    assert "pools overlap" in bad("t1", m)


def test_rejects_exhausted_loopback_pool() -> None:
    def m(d):
        d["pools"]["loopback"] = "10.0.0.0/30"
    assert "loopback pool 10.0.0.0/30" in bad("t1", m)


def test_rejects_exhausted_link_pool() -> None:
    def m(d):
        d["pools"]["link"] = "10.1.0.0/29"
    assert "link pool 10.1.0.0/29 has 4 /31s, 8 links" in bad("t1", m)


def test_rejects_link_to_unknown_node() -> None:
    def m(d):
        d["links"].append({"a": "leaf1", "b": "spine9"})
    assert "unknown node 'spine9'" in bad("t1", m)


def test_rejects_leaf_with_one_uplink() -> None:
    def m(d):
        d["links"] = [lk for lk in d["links"] if lk != {"a": "leaf4", "b": "spine2"}]
    assert "leaf 'leaf4' has 1 uplink(s)" in bad("t1", m)


def test_rejects_unknown_field() -> None:
    def m(d):
        d["routing"]["moed"] = "ospf"
    assert "moed" in bad("t1", m)
