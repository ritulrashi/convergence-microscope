"""The `machine` record that starts every raw results file (ground rule 1)."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FRR_IMAGE_FILE = REPO / "images" / "frr-image.txt"


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20, cwd=REPO)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"unavailable: {e}"
    if out.returncode != 0:
        return f"unavailable: rc={out.returncode} {out.stderr.strip()[:200]}"
    return out.stdout.strip()


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _mem_total_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def frr_image() -> str:
    return FRR_IMAGE_FILE.read_text().strip()


def machine_record() -> dict:
    # results/ is excluded: the run writing this record is itself adding files there.
    status = _run(["git", "status", "--porcelain", "--", ".", ":!results"])
    return {
        "record": "machine",
        "cpu_count": os.cpu_count(),
        "cpu_model": _cpu_model(),
        "mem_total_bytes": _mem_total_bytes(),
        "kernel": platform.release(),
        "docker": _run(["docker", "version", "--format", "{{.Server.Version}}"]),
        "containerlab": _run(["containerlab", "version", "--short"]) or "unknown",
        "frr_image": frr_image(),
        "go": _run(["go", "env", "GOVERSION"]),
        "python": platform.python_version(),
        "git_commit": _run(["git", "rev-parse", "HEAD"]),
        "git_tree_clean": status == "",
    }


if __name__ == "__main__":
    print(json.dumps(machine_record()))
