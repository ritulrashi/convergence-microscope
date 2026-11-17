"""Render a Plan into FRR configs, daemons files, the containerlab topology and
plan.json. Output is a pure function of the plan: no timestamps, stable order."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import yaml
from jinja2 import Environment, PackageLoader, StrictUndefined

from labgen.ipam import Plan, build_plan
from labgen.model import Intent, Mode

HOST_IMAGE = "cm-host:latest"
REPO = Path(__file__).resolve().parent.parent

ROUTER_SYSCTLS = {
    "net.ipv4.ip_forward": 1,
    "net.ipv4.fib_multipath_hash_policy": 1,
    "net.ipv4.conf.all.rp_filter": 0,
    "net.ipv4.conf.default.rp_filter": 0,
    "net.ipv6.conf.all.disable_ipv6": 1,
}


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("labgen", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["network"] = lambda a: str(ipaddress.IPv4Interface(a).network)
    return env


def out_dir_name(plan: Plan) -> str:
    return f"{plan.name}-{plan.mode}" + ("-bfd" if plan.bfd else "")


def lab_name(plan: Plan) -> str:
    return f"cm-{out_dir_name(plan)}"


def clab_topology(plan: Plan, frr_image: str) -> dict:
    nodes: dict[str, dict] = {}
    for r in plan.routers:
        nodes[r.name] = {
            "kind": "linux",
            "image": frr_image,
            "binds": [
                f"{r.name}/frr.conf:/etc/frr/frr.conf",
                f"{r.name}/daemons:/etc/frr/daemons",
                f"{r.name}/vtysh.conf:/etc/frr/vtysh.conf",
            ],
            "sysctls": dict(ROUTER_SYSCTLS),
            # Docker's default route via the management interface would carry
            # packets a router has no fabric route for, hiding blackholes.
            "exec": ["ip route del default"],
            "labels": {"cm-role": r.role},
        }
    for h in plan.hosts:
        nodes[h.name] = {
            "kind": "linux",
            "image": HOST_IMAGE,
            "exec": [
                f"ip addr add {h.address} dev {h.iface}",
                f"ip route add 10.0.0.0/8 via {h.gateway} dev {h.iface}",
            ],
            "labels": {"cm-role": "host"},
        }
    links = [{"endpoints": [f"{lk.a}:{lk.a_iface}", f"{lk.b}:{lk.b_iface}"]} for lk in plan.links]
    return {"name": lab_name(plan), "topology": {"nodes": nodes, "links": links}}


def render(plan: Plan, frr_image: str) -> dict[str, str]:
    """Return {relative path: file content}."""
    env = _env()
    asns = {r.name: r.asn for r in plan.routers}
    files: dict[str, str] = {}
    for r in plan.routers:
        ctx = {"plan": plan, "r": r, "asns": asns}
        files[f"{r.name}/frr.conf"] = env.get_template("frr.conf.j2").render(**ctx)
        files[f"{r.name}/daemons"] = env.get_template("daemons.j2").render(**ctx)
        files[f"{r.name}/vtysh.conf"] = env.get_template("vtysh.conf.j2").render(**ctx)
    files["lab.clab.yml"] = yaml.safe_dump(
        clab_topology(plan, frr_image), sort_keys=False, default_flow_style=False
    )
    files["plan.json"] = json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n"
    return files


def generate(
    intent: Intent, mode: Mode | None, out_root: Path, frr_image: str, bfd: bool | None = None
) -> Path:
    plan = build_plan(intent, mode, bfd)
    out = out_root / out_dir_name(plan)
    for rel, content in sorted(render(plan, frr_image).items()):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode())
    return out
