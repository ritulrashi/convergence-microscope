"""Lab lifecycle and container access."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from labctl.machine import frr_image
from labgen.ipam import Plan, build_plan
from labgen.model import Mode, load_intent
from labgen.render import REPO, generate, lab_name

GENERATED = REPO / "generated"


class CmdError(RuntimeError):
    pass


def run(cmd: list[str], *, check: bool = True, timeout: float = 120, input: str | None = None
        ) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
    if check and p.returncode != 0:
        raise CmdError(f"{' '.join(cmd)} -> rc={p.returncode}: {p.stderr.strip()[:500]}")
    return p


def sudo_prefix() -> list[str]:
    """containerlab and nsenter need root unless we already are root."""
    import os

    return [] if os.geteuid() == 0 else ["sudo", "-E"]


@dataclass
class Lab:
    plan: Plan
    dir: Path

    @property
    def name(self) -> str:
        return lab_name(self.plan)

    @property
    def topo(self) -> Path:
        return self.dir / "lab.clab.yml"

    def container(self, node: str) -> str:
        return f"clab-{self.name}-{node}"

    def exec(self, node: str, *args: str, check: bool = True, timeout: float = 30
             ) -> subprocess.CompletedProcess[str]:
        return run(["docker", "exec", self.container(node), *args], check=check, timeout=timeout)

    def vtysh_json(self, node: str, command: str) -> dict:
        out = self.exec(node, "vtysh", "-c", command).stdout
        return json.loads(out) if out.strip() else {}

    def pid(self, node: str) -> int:
        out = run(["docker", "inspect", "-f", "{{.State.Pid}}", self.container(node)]).stdout
        return int(out.strip())

    def netns_exec(self, node: str, *args: str, timeout: float = 30
                   ) -> subprocess.CompletedProcess[str]:
        """Run a devcontainer binary inside NODE's network namespace."""
        return run([*sudo_prefix(), "nsenter", "-t", str(self.pid(node)), "-n", *args],
                   timeout=timeout)


def load(intent: Path, mode: Mode | None) -> Lab:
    it = load_intent(intent)
    plan = build_plan(it, mode)
    out = generate(it, mode, GENERATED, frr_image())
    return Lab(plan, out)


def ensure_host_image() -> None:
    if run(["docker", "image", "inspect", "cm-host:latest"], check=False).returncode == 0:
        return
    run(["docker", "build", "-f", str(REPO / "images/host/Dockerfile"), "-t", "cm-host:latest",
         str(REPO)], timeout=900)


def up(lab: Lab) -> float:
    """Deploy; return seconds the deploy command took."""
    ensure_host_image()
    if shutil.which("containerlab") is None:
        raise CmdError("containerlab not found")
    t0 = time.monotonic()
    run([*sudo_prefix(), "containerlab", "deploy", "-t", str(lab.topo), "--reconfigure"],
        timeout=600)
    return time.monotonic() - t0


def down(lab: Lab) -> None:
    run([*sudo_prefix(), "containerlab", "destroy", "-t", str(lab.topo), "--cleanup"],
        timeout=300)
