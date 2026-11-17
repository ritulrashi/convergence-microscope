"""`labctl diff`: config drift between a router's running config and its
generated frr.conf.

The generator emits configs in the same order and spelling FRR uses for
`show running-config`, so normalisation only removes lines FRR adds around the
config (banner, version, `!` separators, `end`). A clean deploy diffs empty;
that is a tested property, not an assumption.
"""

from __future__ import annotations

import difflib

DROP_PREFIXES = ("Building configuration", "Current configuration", "frr version", "end")


def normalize(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        s = line.rstrip()
        if not s.strip() or s.strip() == "!" or s.startswith(DROP_PREFIXES):
            continue
        out.append(s)
    return out


def diff(generated: str, running: str, name: str = "") -> list[str]:
    return list(
        difflib.unified_diff(
            normalize(generated),
            normalize(running),
            f"generated/{name}",
            f"running/{name}",
            lineterm="",
            n=1,
        )
    )
