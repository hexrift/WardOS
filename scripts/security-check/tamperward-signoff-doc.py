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
hit in practice on PR #318 after the doc's older guidance (an abbreviated SHA
prefix) was followed. The canonical mechanism is the compact, head-bound
`tw1:` token from `tamperward signoff-label`.

PR #323's review spent three rounds proving that "does this sentence claim a
legacy label's SHA prefix is accepted" cannot be decided by a regex-based
negation heuristic: clause splitting fixed a trailing "not full SHAs", a
verb-adjacent negation window then fixed a causal "because ... do not fit",
and a fourth paraphrase ("do not require full SHAs and accept abbreviated
prefixes" - negating an earlier, unrelated verb within lookback range of the
real one) defeated that too. Each fix closed one instance without closing the
pattern: natural language admits unbounded paraphrases of "accepted, but
worded so a fixed-size negation search misses it".

This check does not try to decide that question from prose at all. Instead it
enforces where the document is allowed to discuss the question:

- The word "prefix" may only appear, in prose, inside the single reviewed
  block in section 4.4 delimited by the `tamperward-prefix-guidance:
  reviewed-block:start`/`:end` HTML comments. Any other prose mention -
  wherever it's phrased, however it's negated or not - fails the check,
  because it's guidance about prefixes that was never reviewed for this
  invariant at all.
- That reviewed block's exact content is pinned by a SHA-256 hash
  (PINNED_BLOCK_SHA256 below). Any edit to it - including a rewording that
  reintroduces the false claim, or a rewording that's perfectly fine -
  changes the hash and fails the check, forcing the new wording to be
  reviewed by a human and the pin updated in the same diff. That diff is
  itself in scripts/security-check/**, a protected/reviewed CI-config
  surface under .tamperward.yml, so it cannot land unreviewed either.

This trades "catches an arbitrary bad paraphrase automatically" (impossible
with a bounded amount of regex) for "any change to what the document claims
about prefixes is a visible, reviewable diff" (mechanically guaranteed).
"""
import argparse
import hashlib
import os
import re
import sys

DEFAULT_WORKFLOW = ".github/workflows/tamperward.yml"
DEFAULT_DOC = "docs/development-under-tamperward.md"

PIN_RE = re.compile(r"tamperward@([0-9]+\.[0-9]+\.[0-9]+)")

CODE_SPAN_RE = re.compile(r"```.*?```|`[^`\n]*`", re.DOTALL)
PREFIX_WORD_RE = re.compile(r"\bprefix(es)?\b", re.IGNORECASE)

BLOCK_START = "<!-- tamperward-prefix-guidance:reviewed-block:start -->"
BLOCK_END = "<!-- tamperward-prefix-guidance:reviewed-block:end -->"

# sha256 of the reviewed block's exact current content (the two bullets
# between BLOCK_START and BLOCK_END in docs/development-under-tamperward.md,
# not including the markers themselves). Recompute and update deliberately
# whenever that block's wording changes, after a human re-reads the new
# wording for correctness against the pinned tamperward CLI - never as a
# mechanical step to make this check pass again.
PINNED_BLOCK_SHA256 = "a0fd2329c5d98e7b2648096f60b5ccbe8606adfb558d9ca17fd0e169ea60fbe3"

# The canonical, currently-working mechanism must stay documented.
REQUIRED_PHRASES = ["tw1:", "signoff-label"]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def pinned_versions(text):
    return set(PIN_RE.findall(text))


def extract_reviewed_block(doc):
    """(block_content, doc_with_block_removed), or (None, doc) if absent."""
    start = doc.find(BLOCK_START)
    end = doc.find(BLOCK_END)
    if start == -1 or end == -1 or end < start:
        return None, doc
    content_start = start + len(BLOCK_START)
    block = doc[content_start:end]
    rest = doc[:start] + doc[end + len(BLOCK_END) :]
    return block, rest


def check_prefix_guidance(doc, doc_path, pinned_sha256):
    """Structural checks: location-constrained + content-pinned (see module docstring)."""
    problems = []
    block, rest = extract_reviewed_block(doc)
    if block is None:
        problems.append(
            f"{doc_path}: missing the `{BLOCK_START}` / `{BLOCK_END}` reviewed-block "
            "markers around section 4.4's legacy-label/prefix bullets - this document "
            "has no reviewed home for that guidance without them"
        )
        return problems

    rest_prose = CODE_SPAN_RE.sub(" ", rest)
    m = PREFIX_WORD_RE.search(rest_prose)
    if m:
        ctx = rest_prose[max(0, m.start() - 60) : m.end() + 60].strip()
        problems.append(
            f"{doc_path}: 'prefix' appears in prose outside the reviewed "
            f"tamperward-prefix-guidance block (issue #320): ...{ctx}... - guidance "
            "about a SHA prefix's acceptance may only live inside that reviewed, "
            "hash-pinned block; move it there (and get it reviewed) or remove it"
        )

    digest = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if digest != pinned_sha256:
        problems.append(
            f"{doc_path}: the reviewed legacy-label/prefix guidance block's content "
            f"changed (sha256 {digest} != pinned {pinned_sha256}) - this is the "
            "one place this document may say whether a legacy label's SHA prefix is "
            "accepted, so any edit to it needs a human to re-read the new wording for "
            "correctness against the pinned tamperward CLI, then update "
            "PINNED_BLOCK_SHA256 in this checker to match, in the same pull request"
        )

    return problems


def check(workflow_path, doc_path, pinned_sha256=PINNED_BLOCK_SHA256):
    """Return a list of problem strings; empty means everything checks out."""
    problems = []

    workflow = read(workflow_path)
    doc = read(doc_path)

    workflow_pins = pinned_versions(workflow)
    if not workflow_pins:
        problems.append(f"{workflow_path}: no `tamperward@<version>` pin found")
        workflow_pins = set()
    elif len(workflow_pins) > 1:
        problems.append(
            f"{workflow_path}: inconsistent tamperward pins across jobs: {sorted(workflow_pins)}"
        )

    if workflow_pins:
        pinned = sorted(workflow_pins)[0]
        doc_pins = pinned_versions(doc)
        stale = doc_pins - workflow_pins
        if stale:
            problems.append(
                f"{doc_path}: references stale tamperward version(s) {sorted(stale)} "
                f"alongside the pinned tamperward@{pinned} - section 4.4 must name only "
                "the version tamperward.yml actually runs"
            )
        if pinned not in doc_pins:
            problems.append(
                f"{doc_path}: does not mention the pinned tamperward@{pinned} - update "
                "section 4.4's sign-off mechanics alongside any pin bump in tamperward.yml"
            )

    problems.extend(check_prefix_guidance(doc, doc_path, pinned_sha256))

    for phrase in REQUIRED_PHRASES:
        if phrase not in doc:
            problems.append(
                f"{doc_path}: missing '{phrase}' - the compact tw1: signoff-label token "
                "is the canonical out-of-band sign-off mechanism and must stay documented"
            )

    return problems, sorted(workflow_pins)[0] if workflow_pins else "?"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--doc", default=DEFAULT_DOC)
    parser.add_argument(
        "--pinned-sha256",
        default=PINNED_BLOCK_SHA256,
        help="Override for testing; production runs use the real doc's own pin.",
    )
    args = parser.parse_args()

    if args.workflow == DEFAULT_WORKFLOW and args.doc == DEFAULT_DOC:
        os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    problems, pinned = check(args.workflow, args.doc, args.pinned_sha256)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"tamperward-signoff-doc: PASS (pin tamperward@{pinned} matches docs)")


if __name__ == "__main__":
    main()
