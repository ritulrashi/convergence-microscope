"""Start and stop the Go recorder (one per router netns) and probers (one per host)."""

from __future__ import annotations

import json
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from labctl.lab import Lab, run, sudo_prefix
from labgen.render import REPO

BUILD = REPO / "build"


def build_go() -> None:
    """Build the Go binaries into build/ (GOROOT per ADR-004 when present)."""
    run(["make", "-s", "-C", str(REPO), "build"], timeout=600)


@dataclass
class Recorder:
    router: str
    out: Path
    proc: subprocess.Popen


def start_recorders(
    lab: Lab,
    out_dir: Path,
    routers: list[str] | None = None,
    raw: bool = False,
    timeout_s: float = 15,
) -> list[Recorder]:
    out_dir.mkdir(parents=True, exist_ok=True)
    recs = []
    for name in routers or [r.name for r in lab.plan.routers]:
        out = out_dir / f"fib_{name}.jsonl"
        ready = out_dir / f".ready_{name}"
        ready.unlink(missing_ok=True)
        cmd = [
            *sudo_prefix(),
            str(BUILD / "recorder"),
            "-router",
            name,
            "-netns",
            f"/proc/{lab.pid(name)}/ns/net",
            "-out",
            str(out),
            "-ready",
            str(ready),
        ]
        if raw:
            cmd += ["-raw", str(out_dir / f"fib_{name}.raw")]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        recs.append(Recorder(name, out, p))
    deadline = time.monotonic() + timeout_s
    for r in recs:
        ready = out_dir / f".ready_{r.router}"
        while not ready.exists():
            if r.proc.poll() is not None:
                raise RuntimeError(f"recorder {r.router} exited: {r.proc.stderr.read()}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"recorder {r.router} not ready")
            time.sleep(0.05)
        ready.unlink()
    return recs


def stop_recorders(recs: list[Recorder]) -> list[dict]:
    """Stop recorders and return their final stats records."""
    for r in recs:
        r.proc.send_signal(signal.SIGTERM)  # sudo relays it to the recorder
    stats = []
    for r in recs:
        try:
            r.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            r.proc.kill()
        last = r.out.read_text().strip().splitlines()[-1:] if r.out.exists() else []
        rec = json.loads(last[0]) if last else {}
        if rec.get("kind") != "stats":
            rec = {
                "kind": "stats",
                "router": r.router,
                "valid": False,
                "invalid_reason": "recorder wrote no stats record",
            }
        stats.append(rec)
    return stats


def merge_fib_events(recs: list[Recorder], out: Path) -> int:
    """Concatenate per-router outputs into one fib_events.jsonl sorted by time."""
    rows = []
    for r in recs:
        for line in r.out.read_text().splitlines():
            if line.strip():
                rows.append(json.loads(line))
    rows.sort(key=lambda x: (x.get("t", 0), x.get("router", ""), x.get("prefix", "")))
    with out.open("w") as f:
        for x in rows:
            f.write(json.dumps(x, sort_keys=True) + "\n")
    return len(rows)


# --- probers -------------------------------------------------------------------


def host_ids(lab: Lab) -> dict[str, int]:
    return {h.name: h.site for h in lab.plan.hosts}


@dataclass
class ProbeRun:
    procs: dict[str, subprocess.Popen]
    start_ns: int


def start_probers(
    lab: Lab,
    rate: int,
    duration_s: float,
    pairs: list[tuple[str, str]] | None = None,
    lead_s: float = 1.0,
    tolerance_ms: float = 5.0,
    grace_s: float = 2.0,
) -> ProbeRun:
    """Start one prober per host. All share start_ns (CLOCK_MONOTONIC, shared kernel)."""
    ids = host_ids(lab)
    addr = {h.name: h.address.split("/")[0] for h in lab.plan.hosts}
    if pairs is None:
        pairs = [(a, b) for a in ids for b in ids if a != b]
    start_ns = time.monotonic_ns() + int(lead_s * 1e9)
    procs = {}
    for h in ids:
        dsts = ",".join(f"{ids[b]}={addr[b]}" for a, b in pairs if a == h)
        cmd = [
            "docker",
            "exec",
            lab.container(h),
            "prober",
            "-id",
            str(ids[h]),
            "-rate",
            str(rate),
            "-start-at",
            str(start_ns),
            "-duration",
            f"{duration_s}s",
            "-grace",
            f"{grace_s}s",
            "-tolerance",
            f"{tolerance_ms}ms",
            "-out",
            "/tmp/probes.jsonl",
        ]
        if dsts:
            cmd += ["-dst", dsts]
        procs[h] = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
    return ProbeRun(procs, start_ns)


def wait_probers(lab: Lab, pr: ProbeRun, out: Path, timeout_s: float) -> list[dict]:
    """Wait, collect every host's output into one probes.jsonl, return stats records."""
    stats = []
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for h, p in pr.procs.items():
            try:
                p.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                p.kill()
            tmp = out.parent / f".probes_{h}.jsonl"
            run(["docker", "cp", f"{lab.container(h)}:/tmp/probes.jsonl", str(tmp)])
            for line in tmp.read_text().splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("k") == "stats":
                    rec["host"] = h
                    if p.returncode != 0:
                        rec["valid"] = False
                        rec["invalid_reason"] = (
                            f"prober exit {p.returncode}: {p.stderr.read()[:200]}"
                        )
                    stats.append(rec)
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            tmp.unlink()
    return stats


# --- tracer --------------------------------------------------------------------


@dataclass
class Tracer:
    out: Path
    proc: subprocess.Popen


def start_tracer(lab: Lab, out: Path, timeout_s: float = 20) -> Tracer:
    """One tracer for the whole lab: every router and host netns is named."""
    out.parent.mkdir(parents=True, exist_ok=True)
    ready = out.parent / ".ready_tracer"
    ready.unlink(missing_ok=True)
    cmd = [*sudo_prefix(), str(BUILD / "tracer"), "-out", str(out), "-ready", str(ready)]
    for n in [r.name for r in lab.plan.routers] + [h.name for h in lab.plan.hosts]:
        cmd += ["-ns", f"{n}=/proc/{lab.pid(n)}/ns/net"]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout_s
    while not ready.exists():
        if p.poll() is not None:
            raise RuntimeError(f"tracer exited: {p.stderr.read()}")
        if time.monotonic() > deadline:
            p.kill()
            raise TimeoutError("tracer not ready")
        time.sleep(0.05)
    ready.unlink()
    return Tracer(out, p)


def stop_tracer(t: Tracer) -> dict:
    t.proc.send_signal(signal.SIGTERM)  # sudo relays it
    try:
        t.proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        # Killing sudo does not kill its child; find the tracer by its output path.
        run([*sudo_prefix(), "pkill", "-KILL", "-f", f"-out {t.out}"], check=False)
        t.proc.wait(timeout=5)
    last = t.out.read_text().strip().splitlines()[-1:] if t.out.exists() else []
    try:
        rec = json.loads(last[0]) if last else {}
    except json.JSONDecodeError:
        rec = {}
    if rec.get("kind") != "stats":
        rec = {"kind": "stats", "valid": False, "invalid_reason": "tracer wrote no stats record"}
    return rec


def read_hops(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            x = json.loads(line)
            if "ev" in x:
                out.append(x)
    return out
