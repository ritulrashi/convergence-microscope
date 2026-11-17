"""Loss attribution on a hand-built run directory with known answers."""

from __future__ import annotations

import json
from pathlib import Path

from labctl.report import attribute, timeline_html

MS = 1_000_000
T_EV = 10_000 * MS


def write(d: Path, name: str, rows) -> None:
    p = d / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(rows, list):
        p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    else:
        p.write_text(json.dumps(rows))


def pred(src, dst, sp, seq, t_ms, observed, predicted="delivered", path=None):
    return {
        "src": src,
        "dst": dst,
        "sp": sp,
        "seq": seq,
        "t_send": T_EV + int(t_ms * MS),
        "observed": observed,
        "predicted": predicted,
        "match": observed == predicted,
        "path": path or [],
    }


def make_run(d: Path, tier: str = "A") -> None:
    write(
        d,
        "run.json",
        {
            "run_id": "t2-ospf-carrier_down-s1",
            "valid": True,
            "invalid_reasons": [],
            "event_t_ns": T_EV,
            "probe_start_ns": T_EV - 2000 * MS,
            "probe_end_ns": T_EV + 6000 * MS,
            "topology": "mesh",
            "mode": "ospf",
            "bfd": False,
            "event": "carrier_down",
            "location": "r3:eth2-r4",
            "seed": 1,
        },
    )
    write(
        d,
        "plan.json",
        {
            "routers": [{"name": n} for n in ("r2", "r3", "r4")],
            "hosts": [{"name": n} for n in ("h3", "h4")],
        },
    )
    write(
        d,
        "replay/summary.json",
        {"tier": tier, "probes": 1000, "fate_agreement": 0.9, "fate_agreement_n": 10},
    )
    write(
        d,
        "replay/predictions.jsonl",
        [
            pred("h3", "h4", 40000, 1, 1.0, "blackhole", "blackhole", ["r3", "DROP(x)@r3"]),
            pred("h3", "h4", 40000, 5, 5.0, "blackhole", "blackhole"),
            pred("h3", "h4", 40001, 2, 2.0, "loop", "loop", ["r3", "r2", "r3", "DROP(y)@r2"]),
            pred("h3", "h4", 40001, 6, 30.0, "loop", "loop"),
            pred("h4", "h3", 40002, 3, 3.0, "other:NEIGH_FAILED", "delivered"),
            pred("h4", "h3", 40003, 4, 4.0, "unknown", "ambiguous"),
            pred("h3", "h4", 40002, 7, -1.0, "delivered", "ambiguous"),  # predicted only
        ],
    )
    write(
        d,
        "replay/loops.jsonl",
        [
            {
                "dst": "10.10.4.10",
                "routers": ["r2", "r3"],
                "start": T_EV + 1 * MS,
                "end": T_EV + 31 * MS,
                "duration_ns": 30 * MS,
            },
            {  # ended before the event: not counted
                "dst": "10.10.4.10",
                "routers": ["r2", "r3"],
                "start": T_EV - 50 * MS,
                "end": T_EV - 40 * MS,
                "duration_ns": 10 * MS,
            },
        ],
    )
    write(
        d,
        "fib_events.jsonl",
        [
            {"kind": "init", "router": "r3", "t": 0, "prefix": "10.10.4.0/24", "new": []},
            {
                "kind": "fib",
                "router": "r3",
                "t": T_EV + 1 * MS,
                "prefix": "10.10.4.0/24",
                "old": ["a"],
                "new": ["b"],
                "via": "link-flush",
            },
            {
                "kind": "fib",
                "router": "r2",
                "t": T_EV + 31 * MS,
                "prefix": "10.10.4.0/24",
                "old": ["c"],
                "new": ["d"],
                "via": "event",
            },
        ],
    )


def test_attribution_tier_a(tmp_path: Path) -> None:
    make_run(tmp_path)
    r = attribute(tmp_path)
    assert r["lost"] == 6
    assert r["lost_by_cause"] == {"blackhole": 2, "microloop": 2, "other": 1, "unknown": 1}
    assert r["cause_source"] == "observed (tracer)"
    w = r["loss_window_per_flow"]
    assert w["h3>h4:40000"] == {
        "lost": 2,
        "first_lost_ms": 1.0,
        "last_lost_ms": 5.0,
        "window_ms": 4.0,
    }
    assert w["h3>h4:40001"]["window_ms"] == 28.0
    assert r["flows_with_loss"] == 4
    assert r["microloops_in_fib"] == 1
    assert r["microloops"][0] == {
        "dst": "10.10.4.10",
        "routers": ["r2", "r3"],
        "start_ms": 1.0,
        "duration_ms": 30.0,
    }
    assert r["convergence_last_fib_change_ms"] == 31.0
    assert r["convergence_last_loss_ms"] == 30.0


def test_attribution_tier_b_uses_predictions(tmp_path: Path) -> None:
    make_run(tmp_path, tier="B")
    r = attribute(tmp_path)
    assert r["cause_source"] == "predicted, not observed"
    # predicted: blackhole x2, loop x2, delivered x1 (unknown), ambiguous x1 (unknown)
    assert r["lost_by_cause"] == {"blackhole": 2, "microloop": 2, "other": 0, "unknown": 2}


def test_timeline_is_self_contained(tmp_path: Path) -> None:
    make_run(tmp_path)
    page = timeline_html(tmp_path, attribute(tmp_path))
    assert "<svg" in page and "<script>" in page
    assert "http://" not in page and "https://" not in page
    assert page.count('class="lost ') == 6
    assert page.count('class="fib"') == 2
    assert "prefers-color-scheme: dark" in page
