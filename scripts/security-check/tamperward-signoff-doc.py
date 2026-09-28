#!/usr/bin/env python3
"""Fail when TamperWard sign-off guidance drifts from the pinned CLI version.

docs/development-under-tamperward.md documents how a maintainer clears a masked
`tamperward-verify` failure out-of-band. That guidance describes specific
behavior of the pinned `tamperward` CLI (.github/workflows/tamperward.yml).

Issue #320: under `tamperward@2.33.0`, `oobToken` requires a legacy
`tamperward:allow:<rule>@<sha>` label's SHA to equal the FULL head object id
once a head is supplied (this workflow always supplies one) - a prefix is
rejected outright. A label's SHA portion is capped at 26 characters by
GitHub's 50-character label-name limit, so it can never equal a full
40-character SHA: the legacy path cannot clear a check here at all. This was
hit in practice on PR #318 after the doc's older guidance (an abbreviated
SHA prefix) was followed. The canonical mechanism is the compact, head-bound
`tw1:` token from `tamperward signoff-label`.

This check keeps the doc's stated pin and described mechanics from silently
drifting away from the workflow again, and keeps the specific, now-false
"accepts a SHA prefix" claim from being reintroduced.
"""
import os
import re
import sys

WORKFLOW = ".github/workflows/tamperward.yml"
DOC = "docs/development-under-tamperward.md"

PIN_RE = re.compile(r"tamperward@([0-9]+\.[0-9]+\.[0-9]+)")

# The specific, now-false claim that the pinned CLI accepts a SHA *prefix* for
# a legacy label's out-of-band sign-off (issue #320). Reintroducing this
# phrase means the doc is telling maintainers to use a mechanism that cannot
# work against this repository's workflow configuration.
BANNED_PHRASES = [
    "accepts any *prefix* of the head SHA",
]

# The canonical, currently-working mechanism must stay documented.
REQUIRED_PHRASES = [
    "tw1:",
    "signoff-label",
]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main():
    problems = []

    workflow = read(WORKFLOW)
    doc = read(DOC)

    workflow_pins = set(PIN_RE.findall(workflow))
    if not workflow_pins:
        problems.append(f"{WORKFLOW}: no `tamperward@<version>` pin found")
    elif len(workflow_pins) > 1:
        problems.append(
            f"{WORKFLOW}: inconsistent tamperward pins across jobs: {sorted(workflow_pins)}"
        )

    doc_pins = set(PIN_RE.findall(doc))
    if workflow_pins and not (doc_pins & workflow_pins):
        pinned = sorted(workflow_pins)[0]
        problems.append(
            f"{DOC}: does not mention the pinned tamperward@{pinned} "
            f"(found: {sorted(doc_pins) or 'none'}) - update section 4.4's sign-off "
            "mechanics alongside any pin bump in tamperward.yml"
        )

    for phrase in BANNED_PHRASES:
        if phrase in doc:
            problems.append(
                f"{DOC}: still claims '{phrase}' - false under the pinned CLI, which "
                "requires an exact full head object id for a legacy label, not a "
                "prefix match (issue #320)"
            )

    for phrase in REQUIRED_PHRASES:
        if phrase not in doc:
            problems.append(
                f"{DOC}: missing '{phrase}' - the compact tw1: signoff-label token is "
                "the canonical out-of-band sign-off mechanism and must stay documented"
            )

    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    pinned = sorted(workflow_pins)[0] if workflow_pins else "?"
    print(f"tamperward-signoff-doc: PASS (pin tamperward@{pinned} matches docs)")


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    main()
