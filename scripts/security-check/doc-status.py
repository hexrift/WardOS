#!/usr/bin/env python3
"""Fail when a document claims the project's phase itself (ADR-0019, decision 7).

The phase lives in docs/status.toml. The README's Status section restates it and must
agree; docs/roadmap.md is the phase plan and may name any phase. Every other Markdown
file under docs/ (decision records included) and every other part of the README may
refer to a phase as a plan ("Phase 7 target") but may not state one as the current
phase: a `Status:` line naming a phase, a heading that pairs "Status" with a phase, or
a phase said to be "in progress", "current", "started", "underway" or "now".
"""
import glob
import os
import re
import sys

STATUS_FILE = "docs/status.toml"
PLAN_FILES = {"docs/roadmap.md"}
PHASE = re.compile(r"\bPhase\s+(\d+)\b")
# "Phase 6 … in progress", "Phase 0 (this repository, now)", "currently in Phase 3".
CURRENCY = re.compile(
    r"\bPhase\s+\d+\b[^.\n]{0,40}\b(in progress|current|currently|now|started|underway)\b"
    r"|\b(current|currently|now)\b[^.\n]{0,20}\bPhase\s+\d+\b",
    re.IGNORECASE,
)


def declared_phase(path):
    """The `phase = N` of status.toml; a tiny parser so the check needs no library."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\s*phase\s*=\s*(\d+)\s*(#.*)?$", line)
            if m:
                return int(m.group(1))
    sys.exit(f"doc-status: {path} declares no `phase = N`")


def status_paragraph(lines):
    """The lines of the document's own `Status:` paragraph (first one, if any)."""
    for i, line in enumerate(lines):
        if line.startswith("Status:"):
            para = []
            for cont in lines[i:]:
                if not cont.strip():
                    break
                para.append(cont)
            return i + 1, " ".join(para)
    return None, ""


def check_document(path, lines):
    """Phase claims a document makes about itself, as `path:line: text` strings."""
    found = []
    start, para = status_paragraph(lines)
    if start is not None and PHASE.search(para):
        found.append(f"{path}:{start}: the Status line claims a phase: {para[:80]}")
    for n, line in enumerate(lines, 1):
        if line.startswith("#") and "status" in line.lower() and PHASE.search(line):
            found.append(f"{path}:{n}: a Status heading claims a phase: {line.strip()}")
        elif CURRENCY.search(line):
            found.append(f"{path}:{n}: a phase is claimed as current: {line.strip()[:80]}")
    return found


def check_readme(path, lines, phase):
    """The README states the phase once, in its Status section, and it matches."""
    found = []
    in_status = False
    stated = None
    for n, line in enumerate(lines, 1):
        if line.startswith("## "):
            in_status = line.strip() == "## Status"
            continue
        if in_status:
            if stated is None:
                m = PHASE.search(line)
                if m:
                    stated = int(m.group(1))
                    if stated != phase:
                        found.append(
                            f"{path}:{n}: README says Phase {stated}, "
                            f"{STATUS_FILE} says Phase {phase}"
                        )
        elif PHASE.search(line):
            found.append(f"{path}:{n}: a phase outside the Status section: {line.strip()[:80]}")
    if stated is None:
        found.append(f"{path}: the Status section names no phase ({STATUS_FILE} says {phase})")
    return found


def main():
    phase = declared_phase(STATUS_FILE)
    problems = []
    for path in sorted(glob.glob("docs/**/*.md", recursive=True)):
        if path in PLAN_FILES:
            continue
        with open(path, encoding="utf-8") as fh:
            problems += check_document(path, fh.read().split("\n"))
    with open("README.md", encoding="utf-8") as fh:
        problems += check_readme("README.md", fh.read().split("\n"), phase)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"doc-status: PASS (Phase {phase} in {STATUS_FILE} and README; no document claims its own)")


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    main()
