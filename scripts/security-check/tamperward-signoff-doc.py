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
real one) defeated that too. A fourth round then showed that scoping WHERE
such prose may appear by the single word "prefix" has the identical problem
one level up: "legacy labels accept abbreviated head SHAs" carries the same
meaning without that word, so it could be added right next to the reviewed
guidance and never be flagged as needing review at all.

This check does not try to decide that question from prose, or name every
word that could carry its meaning. Instead it pins the entire structural
section the question can legitimately be answered in:

- Section 4.4 in its entirety - from the `tamperward-prefix-guidance:
  reviewed-block:start` marker right after its heading to the matching
  `:end` marker before section 5 - is pinned by a SHA-256 hash
  (PINNED_BLOCK_SHA256 below). Any edit anywhere in that section - a
  reintroduced false claim, an unrelated typo fix, a wording that avoids
  every word this checker could have listed - changes the hash and fails
  the check, forcing a human to read the new section and update the pin in
  the same diff. That diff is itself in scripts/security-check/**, a
  protected/reviewed CI-config surface under .tamperward.yml, so it cannot
  land unreviewed either. This is the actual guarantee: not "no bad
  paraphrase can be written" (impossible to prove with any amount of
  regex), but "no change to this section's content, however it's worded,
  reaches main without a human reading it".
- As a secondary, best-effort signal only - not the mechanism the above
  guarantee depends on - the word "prefix" is also checked outside section
  4.4 entirely, since that section is this document's one dedicated home
  for the topic and a mention anywhere else is worth a human's attention
  even though, per the above, this single word cannot be relied on to catch
  every phrasing.
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

# sha256 of section 4.4's exact current content (everything between
# BLOCK_START and BLOCK_END in docs/development-under-tamperward.md, not
# including the markers themselves - the whole section, not just the two
# bullets that discuss the legacy label directly). Recompute and update
# deliberately whenever anything in that section changes, after a human
# re-reads the new content for correctness against the pinned tamperward
# CLI - never as a mechanical step to make this check pass again.
PINNED_BLOCK_SHA256 = "713a88f14caebb7601475f1fdf313f346e6de7e91e698de31e24185ddb8e7230"

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
    """Structural checks: whole-section content pin, plus a best-effort location signal."""
    problems = []
    block, rest = extract_reviewed_block(doc)
    if block is None:
        problems.append(
            f"{doc_path}: missing the `{BLOCK_START}` / `{BLOCK_END}` reviewed-block "
            "markers around section 4.4 (Out-of-band sign-off mechanics) - this document "
            "has no reviewed, hash-pinned home for that section without them"
        )
        return problems

    rest_prose = CODE_SPAN_RE.sub(" ", rest)
    m = PREFIX_WORD_RE.search(rest_prose)
    if m:
        ctx = rest_prose[max(0, m.start() - 60) : m.end() + 60].strip()
        problems.append(
            f"{doc_path}: 'prefix' appears in prose outside section 4.4's reviewed, "
            f"hash-pinned block (issue #320): ...{ctx}... - section 4.4 is this "
            "document's one dedicated home for legacy-label SHA-prefix guidance; move "
            "this there (and get it reviewed) or remove it. (This single-word check is "
            "a best-effort signal, not the guarantee - see the module docstring.)"
        )

    digest = hashlib.sha256(block.encode("utf-8")).hexdigest()
    if digest != pinned_sha256:
        problems.append(
            f"{doc_path}: section 4.4's content changed (sha256 {digest} != pinned "
            f"{pinned_sha256}) - this section is pinned in full because it's this "
            "document's one place to say whether a legacy label's SHA prefix is "
            "accepted, however that's phrased; any edit to it needs a human to "
            "re-read the new content for correctness against the pinned tamperward "
            "CLI, then update "
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
