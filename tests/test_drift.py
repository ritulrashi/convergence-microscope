"""Drift: generated configs match FRR 10.7.1 running configs captured from clean
deploys, and injected changes are reported."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from labctl.drift import diff
from labctl.verify import check_peers
from labgen.ipam import build_plan
from labgen.model import Mode, load_intent
from labgen.render import render

REPO = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures" / "frr"
RUNNING = sorted((FIX / "running").glob("*_running.conf"))
INTENT = {"t1": REPO / "intent/t1-leafspine.yaml", "t2": REPO / "intent/t2-mesh.yaml"}


def generated(name: str) -> tuple[str, str]:
    t, mode, node, *rest = name.split("_")
    bfd = "bfd" in rest
    plan = build_plan(load_intent(INTENT[t]), Mode(mode), bfd)
    return render(plan, "x")[f"{node}/frr.conf"], node


@pytest.mark.parametrize("path", RUNNING, ids=[p.stem for p in RUNNING])
def test_clean_deploy_has_no_drift(path: Path) -> None:
    gen, node = generated(path.name)
    assert diff(gen, path.read_text(), node) == []


def test_injected_cost_change_is_drift() -> None:
    path = FIX / "running" / "t2_ospf_r3_running.conf"
    gen, node = generated(path.name)
    running = path.read_text().replace(" ip ospf cost 10", " ip ospf cost 99", 1)
    d = diff(gen, running, node)
    assert "- ip ospf cost 10" in d and "+ ip ospf cost 99" in d


def test_banner_lines_are_ignored() -> None:
    assert diff("hostname a\n", "Building configuration...\n!\nfrr version 1\nhostname a\nend\n") == []


def test_ospf_and_isis_neighbor_parsing() -> None:
    plan = build_plan(load_intent(INTENT["t2"]), Mode.ospf)
    nbr = json.loads((FIX / "t2_ospf_r3_nbr.json").read_text())
    assert check_peers(plan, plan.router("r3"), nbr) == []
    plan = build_plan(load_intent(INTENT["t2"]), Mode.isis)
    nbr = json.loads((FIX / "t2_isis_r3_nbr.json").read_text())
    assert check_peers(plan, plan.router("r3"), nbr) == []
