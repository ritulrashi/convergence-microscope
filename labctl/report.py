"""Loss attribution and the per-run timeline (SPEC 5.7, 5.8).

Reads a run directory after `replay` has run and writes:
  report.json    lost packets by cause, loss window per flow, microloops,
                 convergence time
  timeline.html  self-contained page: routers down the side, time across,
                 the event, every FIB change, every lost packet coloured by
                 cause, microloop intervals. Inline SVG and JS, no CDN.

Cause is the observed one in Tier A (drop reason from the tracer, classified
with the calibrated codes), else the replay prediction, labelled as such.
"""

from __future__ import annotations

import gzip
import html
import json
from collections import Counter, defaultdict
from pathlib import Path

CAUSES = ("blackhole", "microloop", "other", "unknown")


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        gz = path.with_suffix(path.suffix + ".gz")
        if not gz.exists():
            return []
        text = gzip.open(gz, "rt").read()
    else:
        text = path.read_text()
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def cause_of(observed: str) -> str:
    if observed == "blackhole":
        return "blackhole"
    if observed == "loop":
        return "microloop"
    if observed.startswith("other"):
        return "other"
    return "unknown"


def attribute(run_dir: Path) -> dict:
    run = json.loads((run_dir / "run.json").read_text())
    summary = json.loads((run_dir / "replay" / "summary.json").read_text())
    preds = _jsonl(run_dir / "replay" / "predictions.jsonl")
    loops = _jsonl(run_dir / "replay" / "loops.jsonl")
    fib = [e for e in _jsonl(run_dir / "fib_events.jsonl") if e.get("kind") == "fib"]
    t_ev = run["event_t_ns"]
    tier_a = summary["tier"] == "A"

    lost = [p for p in preds if p["observed"] != "delivered"]
    by_cause: Counter = Counter()
    for p in lost:
        if tier_a:
            c = cause_of(p["observed"])
        else:
            c = {"blackhole": "blackhole", "loop": "microloop"}.get(p["predicted"], "unknown")
        by_cause[c] += 1

    flows: dict[str, list[int]] = defaultdict(list)
    for p in lost:
        flows[f"{p['src']}>{p['dst']}:{p['sp']}"].append(p["t_send"])
    windows = {
        f: {
            "lost": len(ts),
            "first_lost_ms": round((min(ts) - t_ev) / 1e6, 3),
            "last_lost_ms": round((max(ts) - t_ev) / 1e6, 3),
            "window_ms": round((max(ts) - min(ts)) / 1e6, 3),
        }
        for f, ts in sorted(flows.items())
    }

    after = [lp for lp in loops if lp["end"] > t_ev]
    microloops = [
        {
            "dst": lp["dst"],
            "routers": lp["routers"],
            "start_ms": round((lp["start"] - t_ev) / 1e6, 3),
            "duration_ms": round(lp["duration_ns"] / 1e6, 3),
        }
        for lp in after
    ]
    fib_after = [e["t"] for e in fib if e["t"] >= t_ev]
    lost_after = [p["t_send"] for p in lost if p["t_send"] >= t_ev]
    return {
        "run_id": run["run_id"],
        "valid": run["valid"],
        "invalid_reasons": run.get("invalid_reasons", []),
        "cause_source": "observed (tracer)" if tier_a else "predicted, not observed",
        "probes": summary["probes"],
        "lost": len(lost),
        "lost_by_cause": {c: by_cause.get(c, 0) for c in CAUSES},
        "loss_window_per_flow": windows,
        "flows_with_loss": len(windows),
        "max_flow_window_ms": max((w["window_ms"] for w in windows.values()), default=0.0),
        "microloops_in_fib": len(microloops),
        "microloops": microloops,
        "observed_loop_packets": by_cause.get("microloop", 0),
        "fib_changes_after_event": len(fib_after),
        "convergence_last_fib_change_ms": round((max(fib_after) - t_ev) / 1e6, 3)
        if fib_after
        else None,
        "convergence_last_loss_ms": round((max(lost_after) - t_ev) / 1e6, 3)
        if lost_after
        else None,
        "replay": {
            k: summary.get(k)
            for k in ("fate_agreement", "fate_agreement_n", "path_consistency", "mismatch_classes")
        },
    }


COLORS = {"blackhole": "#d14", "microloop": "#e80", "other": "#73b", "unknown": "#777"}


def timeline_html(run_dir: Path, rep: dict) -> str:
    run = json.loads((run_dir / "run.json").read_text())
    plan = json.loads((run_dir / "plan.json").read_text())
    preds = _jsonl(run_dir / "replay" / "predictions.jsonl")
    loops = _jsonl(run_dir / "replay" / "loops.jsonl")
    fib = [e for e in _jsonl(run_dir / "fib_events.jsonl") if e.get("kind") == "fib"]
    t_ev = run["event_t_ns"]
    t0, t1 = run["probe_start_ns"], run["probe_end_ns"]
    rows = [r["name"] for r in plan["routers"]] + [h["name"] for h in plan["hosts"]]
    row_y = {n: 40 + i * 28 for i, n in enumerate(rows)}
    left, width = 90, 1100
    height = 40 + len(rows) * 28 + 40

    def x(t: int) -> float:
        return left + (t - t0) / max(1, t1 - t0) * width

    out = []
    for n, y in row_y.items():
        out.append(f'<text x="8" y="{y + 4}" class="lbl">{html.escape(n)}</text>')
        out.append(f'<line x1="{left}" y1="{y}" x2="{left + width}" y2="{y}" class="row"/>')
    for lp in loops:
        if lp["end"] < t0 or lp["start"] > t1:
            continue
        xa, xb = x(max(lp["start"], t0)), x(min(lp["end"], t1))
        tip = f"loop to {lp['dst']}: {', '.join(lp['routers'])}, {lp['duration_ns'] / 1e6:.2f} ms"
        for r in lp["routers"]:
            y = row_y.get(r)
            if y is not None:
                out.append(
                    f'<rect class="loop" x="{xa:.1f}" y="{y - 9}" width="{max(2, xb - xa):.1f}"'
                    f' height="18"><title>{html.escape(tip)}</title></rect>'
                )
    for e in fib:
        if t0 <= e["t"] <= t1 and e["router"] in row_y:
            y = row_y[e["router"]]
            tip = f"{e['router']} {e['prefix']}: {e['old']} -> {e['new']} ({e['via']}) at {(e['t'] - t_ev) / 1e6:.3f} ms"
            out.append(
                f'<line class="fib" x1="{x(e["t"]):.1f}" y1="{y - 8}" x2="{x(e["t"]):.1f}" y2="{y + 8}">'
                f"<title>{html.escape(tip)}</title></line>"
            )
    for p in preds:
        if p["observed"] == "delivered":
            continue
        cause = cause_of(p["observed"])
        node = p["src"]
        for hop in reversed(p.get("path") or []):
            node = hop.split("@")[-1]
            break
        y = row_y.get(node, row_y.get(p["src"], 40))
        tip = (
            f"{p['src']}>{p['dst']}:{p['sp']} seq {p['seq']} at {(p['t_send'] - t_ev) / 1e6:.3f} ms:"
            f" observed {p['observed']}, predicted {p['predicted']}"
        )
        out.append(
            f'<circle class="lost {cause}" cx="{x(p["t_send"]):.1f}" cy="{y}" r="2.5" '
            f'fill="{COLORS[cause]}"><title>{html.escape(tip)}</title></circle>'
        )
    xe = x(t_ev)
    out.append(f'<line class="event" x1="{xe:.1f}" y1="20" x2="{xe:.1f}" y2="{height - 30}"/>')
    out.append(f'<text x="{xe + 4:.1f}" y="16" class="lbl">{html.escape(run["event"])}</text>')
    for ms in range(int((t0 - t_ev) / 1e6 // 500) * 500, int((t1 - t_ev) / 1e6) + 1, 500):
        xt = x(t_ev + ms * 1_000_000)
        if left <= xt <= left + width:
            out.append(
                f'<text x="{xt:.1f}" y="{height - 12}" class="tick">{ms} ms</text>'
                f'<line x1="{xt:.1f}" y1="{height - 30}" x2="{xt:.1f}" y2="{height - 24}" class="row"/>'
            )
    svg = "\n".join(out)
    title = f"{run['run_id']}"
    facts = html.escape(
        f"{run['topology']} {run['mode']}{' +BFD' if run['bfd'] else ''}, {run['event']} at "
        f"{run['location']}, seed {run['seed']}. Lost {rep['lost']} of {rep['probes']}: "
        + ", ".join(f"{k} {v}" for k, v in rep["lost_by_cause"].items())
        + f". Cause source: {rep['cause_source']}. Valid: {rep['valid']}."
    )
    legend = " ".join(
        f'<label><input type="checkbox" checked data-c="{c}"> <span style="color:{COLORS[c]}">●</span> {c}</label>'
        for c in CAUSES
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Run timeline</title>
<style>
:root {{ --bg:#fff; --fg:#111; --muted:#888; --grid:#e4e4e4; --fib:#2a6fdb; --loop:rgba(232,128,0,.25); --event:#000; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111; --fg:#eee; --muted:#999; --grid:#2c2c2c; --fib:#6aa0ff; --loop:rgba(255,160,40,.3); --event:#fff; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px system-ui,sans-serif; margin:16px; }}
.lbl {{ fill:var(--fg); font-size:12px; }} .tick {{ fill:var(--muted); font-size:11px; }}
.row {{ stroke:var(--grid); }} .fib {{ stroke:var(--fib); stroke-width:1.5; }}
.loop {{ fill:var(--loop); }} .event {{ stroke:var(--event); stroke-dasharray:4 3; }}
.wrap {{ overflow-x:auto; }} label {{ margin-right:12px; }}
</style></head><body>
<h1 style="font-size:18px">{html.escape(title)}</h1>
<p>{facts}</p>
<p>{legend} <label><input type="checkbox" checked data-k="fib"> FIB changes</label>
<label><input type="checkbox" checked data-k="loop"> microloops (from FIB)</label></p>
<div class="wrap"><svg width="{left + width + 20}" height="{height}" role="img" aria-label="timeline">{svg}</svg></div>
<script>
document.querySelectorAll('input[data-c]').forEach(cb => cb.addEventListener('change', () =>
  document.querySelectorAll('circle.' + cb.dataset.c).forEach(e => e.style.display = cb.checked ? '' : 'none')));
document.querySelectorAll('input[data-k]').forEach(cb => cb.addEventListener('change', () =>
  document.querySelectorAll('.' + cb.dataset.k).forEach(e => e.style.display = cb.checked ? '' : 'none')));
</script>
</body></html>
"""


def write_report(run_dir: Path) -> dict:
    rep = attribute(run_dir)
    (run_dir / "report.json").write_text(json.dumps(rep, indent=2, sort_keys=True) + "\n")
    (run_dir / "timeline.html").write_text(timeline_html(run_dir, rep))
    return rep
