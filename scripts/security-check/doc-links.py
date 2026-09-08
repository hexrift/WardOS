#!/usr/bin/env python3
"""Fail if any relative Markdown link in the repository points at a missing file."""
import glob
import os
import re
import sys

LINK = re.compile(r"\]\(([^)#\s]+)(#[^)]*)?\)")
broken = []
for path in glob.glob("**/*.md", recursive=True):
    if path.startswith("target/"):
        continue
    base = os.path.dirname(path)
    with open(path, encoding="utf-8") as fh:
        for target, _ in LINK.findall(fh.read()):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(base, target))):
                broken.append(f"{path}: {target}")

if broken:
    print("\n".join(broken), file=sys.stderr)
    sys.exit(1)
print("doc-links: PASS")
