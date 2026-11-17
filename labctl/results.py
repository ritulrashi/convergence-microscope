"""Raw results files: JSON Lines whose first record is the machine record."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from labctl.machine import machine_record


class ResultWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._f = path.open("w")
        self.write(machine_record())

    def write(self, rec: dict[str, Any]) -> None:
        self._f.write(json.dumps(rec, sort_keys=True) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> ResultWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
