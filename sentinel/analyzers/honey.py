"""Honey files: decoys with no real data. Any modify, rename, or delete is suspicious."""
from __future__ import annotations

import os
import random

DECOYS = ["_budget_2024.csv", "_passwords_backup.txt", "_tax_records.txt", "_client_list.csv"]


def norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _content(name: str, seed: int) -> bytes:
    rnd = random.Random(seed)
    lines = ["# DECOY FILE created by Sentinel. Contains no real data."]
    for i in range(300):
        lines.append(f"record{i},{rnd.randint(1000, 99999)},{rnd.random():.4f},item-{rnd.randint(1, 500)}")
    return "\n".join(lines).encode()


class HoneyRegistry:
    def __init__(self) -> None:
        self._paths: set[str] = set()

    def deploy(self, directory: str, count: int = 3) -> list[str]:
        os.makedirs(directory, exist_ok=True)
        made = []
        for i, name in enumerate(DECOYS[: max(1, count)]):
            p = os.path.join(directory, name)
            with open(p, "wb") as f:
                f.write(_content(name, i))
            self._paths.add(norm(p))
            made.append(p)
        return made

    def is_honey(self, path: str | None) -> bool:
        return bool(path) and norm(path) in self._paths

    def rename(self, src: str, dst: str) -> None:
        if norm(src) in self._paths:
            self._paths.discard(norm(src))
            self._paths.add(norm(dst))

    @property
    def paths(self) -> list[str]:
        return sorted(self._paths)
