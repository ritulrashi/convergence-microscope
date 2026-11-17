"""Shared helpers for experiment scripts: CPU accounting and summary stats."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "results"


@dataclass
class CpuSample:
    busy: int
    total: int


def cpu_sample() -> CpuSample:
    fields = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = fields[3] + fields[4]  # idle + iowait
    return CpuSample(sum(fields) - idle, sum(fields))


def cpu_util(a: CpuSample, b: CpuSample) -> float:
    """Average utilisation over all CPUs between two samples, 0..1."""
    dt = b.total - a.total
    return (b.busy - a.busy) / dt if dt > 0 else 0.0


def loadavg1() -> float:
    return os.getloadavg()[0]


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile (p in 0..100)."""
    if not values:
        return math.nan
    s = sorted(values)
    k = max(1, math.ceil(p / 100 * len(s)))
    return s[k - 1]


def summarize(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "median": percentile(values, 50),
        "p95": percentile(values, 95),
        "max": max(values) if values else math.nan,
    }
