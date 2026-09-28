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

This check keeps the doc's stated pin from silently drifting away from the
workflow (it must name the one pin the workflow actually runs, and no
other), and keeps any claim that a legacy label accepts an abbreviated SHA
prefix - the exact wording PR #323's review flagged, or a paraphrase of it -
from being reintroduced.
"""
import argparse
import os
import re
import sys

DEFAULT_WORKFLOW = ".github/workflows/tamperward.yml"
DEFAULT_DOC = "docs/development-under-tamperward.md"

PIN_RE = re.compile(r"tamperward@([0-9]+\.[0-9]+\.[0-9]+)")

# A "prefix" clause is one that could be read as guidance, not just a
# glossary mention of the word. It's suspect if it pairs "prefix" with a
# word implying the prefix is accepted/effective, and isn't itself framed
# as false (issue #320, and the paraphrases PR #323's review supplied:
# "... permit ...", "... accept ..., not full SHAs", and "... accept ...
# because full SHAs do not fit").
#
# Two different kinds of "this claim is false" marker are handled
# differently, because they scope differently in English:
#
# - FRAMING_RE (mistaken/wrong/false/rejected/...) is a clause-wide
#   qualifier - "on the mistaken premise that X accepts Y" reads as false
#   regardless of where in the clause "mistaken" sits relative to "accepts".
#   Checked anywhere in the clause.
# - Grammatical negation (not/never/cannot/doesn't/no longer) attaches to
#   whatever verb it's adjacent to, not to the clause as a whole - "accepts
#   abbreviated prefixes, not full SHAs" and "accepts abbreviated prefixes
#   because full SHAs do not fit" both have a "not" in the clause/sentence,
#   but neither negates "accepts": one negates "full SHAs", the other
#   negates "fit". A clause-wide (or sentence-wide) search for these treats
#   any "not" as covering the whole clause and was wrong twice over during
#   review. Checked only in the few words immediately before the positive
#   verb match it would need to negate.
#
# Clause boundaries themselves (, ; — and coordinating/subordinating
# conjunctions, causal ones included) still matter for FRAMING_RE and for
# keeping PREFIX_WORD_RE's match paired with the right verb, so sentences
# are still split into clauses first.
#
# Inline/fenced code spans are stripped before any of this runs. This
# document necessarily contains the literal label name
# `tamperward:allow:<rule>@<sha-prefix>` and similar identifiers verbatim,
# in backticks, while explaining why they don't work - "allow" and "prefix"
# inside a code-formatted identifier are not an English claim about what's
# accepted, and must not be read as one (that false match is exactly what
# adding "allow" to POSITIVE_RE below produced against this doc's own
# `tamperward:allow:verify@...` label name before this stripping existed).
CODE_SPAN_RE = re.compile(r"```.*?```|`[^`\n]*`", re.DOTALL)
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n{2,}")
CLAUSE_SPLIT_RE = re.compile(
    r",|;|—|\b(?:but|however|though|although|while|except|whereas|yet|"
    r"because|since|given that|so that|insofar as)\b",
    re.IGNORECASE,
)
PREFIX_WORD_RE = re.compile(r"\bprefix(es)?\b", re.IGNORECASE)
POSITIVE_RE = re.compile(
    r"\b(accept(s|ed|ing)?|honor(s|ed)?|match(es|ed|ing)?|work(s|ed|ing)?|"
    r"clear(s|ed|ing)?|support(s|ed|ing)?|allow(s|ed|ing)?|permit(s|ted|ting)?|"
    r"enable(s|d|ing)?|grant(s|ed|ing)?|authorize(s|d)?|valid|sufficient|enough)\b",
    re.IGNORECASE,
)
# Clause-wide framing: the claim is presented as false wherever this sits
# in the clause, so no positional check is needed.
FRAMING_RE = re.compile(
    r"\b(reject(s|ed|ing)?|inert|false|stale|incompatible|used to|"
    r"earlier guidance|previously|outdated|wrong|nor|mistaken(ly)?|mistake|"
    r"incorrect(ly)?|erroneous(ly)?)\b",
    re.IGNORECASE,
)
# Grammatical negation: only counts against a specific positive-verb match
# when it sits in the few words immediately before that match (see above).
VERB_NEGATOR_RE = re.compile(
    r"\b(not|never|cannot|can't|doesn't|does not|no longer)\b", re.IGNORECASE
)
# How far back (characters) to look for a verb negator before a positive
# match - wide enough for "does not currently/still/ever accept", narrow
# enough to stay within the same claim rather than an earlier one.
NEGATOR_LOOKBACK = 40


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def pinned_versions(text):
    return set(PIN_RE.findall(text))


def suspect_prefix_sentences(doc):
    """Clauses pairing 'prefix' with an unnegated acceptance claim."""
    prose = CODE_SPAN_RE.sub(" ", doc)
    found = []
    for sentence in SENTENCE_SPLIT_RE.split(prose):
        for clause in CLAUSE_SPLIT_RE.split(sentence):
            if not PREFIX_WORD_RE.search(clause):
                continue
            if FRAMING_RE.search(clause):
                continue
            for m in POSITIVE_RE.finditer(clause):
                lookback = clause[max(0, m.start() - NEGATOR_LOOKBACK) : m.start()]
                if VERB_NEGATOR_RE.search(lookback):
                    continue
                found.append(clause.strip().replace("\n", " ")[:160])
                break
    return found


# The canonical, currently-working mechanism must stay documented.
REQUIRED_PHRASES = ["tw1:", "signoff-label"]


def check(workflow_path, doc_path):
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

    for sentence in suspect_prefix_sentences(doc):
        problems.append(
            f"{doc_path}: sentence reads as claiming a legacy label's SHA prefix is "
            f"accepted/effective, which is false under the pinned CLI (issue #320): "
            f"{sentence!r}"
        )

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
    args = parser.parse_args()

    if args.workflow == DEFAULT_WORKFLOW and args.doc == DEFAULT_DOC:
        os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    problems, pinned = check(args.workflow, args.doc)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"tamperward-signoff-doc: PASS (pin tamperward@{pinned} matches docs)")


if __name__ == "__main__":
    main()
