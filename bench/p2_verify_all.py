"""Phase 2 acceptance: every topology x mode x BFD combination deploys,
passes `verify`, and shows no config drift right after deploy.

Output: results/p2/verify_all.jsonl (machine record, one record per
combination).
"""

from __future__ import annotations

from pathlib import Path

import typer

from bench.common import RESULTS
from labctl import lab as labmod
from labctl.drift import diff
from labctl.results import ResultWriter
from labctl.verify import verify_wait
from labgen.model import Mode

INTENTS = {"t1": "intent/t1-leafspine.yaml", "t2": "intent/t2-mesh.yaml"}


def main(out: Path = RESULTS / "p2" / "verify_all.jsonl", timeout: float = 120) -> None:
    ok_all = True
    with ResultWriter(out) as w:
        for topo, path in INTENTS.items():
            for mode in Mode:
                for bfd in (False, True):
                    lab = labmod.load(Path(path), mode, bfd)
                    try:
                        labmod.down(lab)
                    except labmod.CmdError:
                        pass
                    deploy_s = labmod.up(lab)
                    res, to_pass, attempts = verify_wait(lab, timeout)
                    drifted = {}
                    for r in lab.plan.routers:
                        run = lab.exec(r.name, "vtysh", "-c", "show running-config").stdout
                        d = diff((lab.dir / r.name / "frr.conf").read_text(), run, r.name)
                        if d:
                            drifted[r.name] = d
                    labmod.down(lab)
                    ok = res.ok and not drifted
                    ok_all &= ok
                    w.write(
                        {
                            "record": "combination",
                            "topology": topo,
                            "mode": mode.value,
                            "bfd": bfd,
                            "verify_ok": res.ok,
                            "checks": res.checks,
                            "failures": res.failures,
                            "deploy_s": round(deploy_s, 3),
                            "seconds_to_verify": round(to_pass, 3) if res.ok else None,
                            "attempts": attempts,
                            "routers": len(lab.plan.routers),
                            "routers_drifted": len(drifted),
                            "drift": drifted,
                        }
                    )
                    typer.echo(
                        f"{topo}-{mode.value} bfd={bfd}: verify {res.ok} "
                        f"{res.checks} drift {len(drifted)}/{len(lab.plan.routers)}"
                    )
    if not ok_all:
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
