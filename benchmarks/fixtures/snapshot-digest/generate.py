#!/usr/bin/env python3
"""Regenerate the pinned `tree/` fixture under this directory (issue #150).

Deterministic: a fixed seed and fixed file/size schedule, so re-running this
script reproduces byte-identical output. The generated tree is committed to
git (`tree/`) rather than built at benchmark-run time, so the fixture stays
pinned across machines and revisions per docs/performance.md's methodology
("fixed image digest ... every result records all of these").

Usage: python3 generate.py   (run from this directory; rewrites tree/)
"""

import os
import random
import shutil

SEED = 150  # the issue number, fixed forever for this fixture
FILE_COUNT = 220
MIN_BYTES = 256
MAX_BYTES = 4096
DIRS = ["", "src", "src/nested", "docs", "data/a", "data/b"]

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "tree")


def main() -> None:
    rng = random.Random(SEED)
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    for d in DIRS:
        os.makedirs(os.path.join(OUT, d), exist_ok=True)
    for i in range(FILE_COUNT):
        d = DIRS[i % len(DIRS)]
        size = rng.randint(MIN_BYTES, MAX_BYTES)
        # Deterministic pseudo-text content, not just random bytes, so a
        # human diff of the fixture (if it ever needs to change) is legible.
        line = f"ward-bench fixture file {i:04d} seed={SEED}\n"
        body = (line * (size // len(line) + 1))[:size]
        path = os.path.join(OUT, d, f"file-{i:04d}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)


if __name__ == "__main__":
    main()
