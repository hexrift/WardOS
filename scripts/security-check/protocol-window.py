#!/usr/bin/env python3
"""Fail when the documented node protocol window drifts from the code (issue #275).

docs/compatibility.md promises external control planes a compatibility window: the
`ward-node` protocol range a node serves. The code's single source of that range is
the `WARD_NODE_PROTOCOL` constant in crates/ward-node-protocol/src/lib.rs, whose
`SupportedProtocolRange::valid(major, min_minor, max_minor)` is what `negotiate`
compares a peer's `hello` against.

The doc states the window in one machine-readable marker:

    <!-- protocol-window: 1.0-1.3 -->

This check parses both and fails unless they name the same major and the same minor
bounds. Widening the code (a new minor), retiring a minor or bumping the major
therefore cannot land without the compatibility document saying so in the same diff,
and the reverse: the doc cannot promise a minor the node does not serve. Anything it
cannot parse unambiguously (a missing or duplicated marker, a cross-major or inverted
range, a constant that is not three integer literals) fails rather than passes.
"""
import argparse
import os
import re
import sys

DEFAULT_SOURCE = "crates/ward-node-protocol/src/lib.rs"
DEFAULT_DOC = "docs/compatibility.md"

CONST_DECL_RE = re.compile(r"\bconst\s+WARD_NODE_PROTOCOL\b")
CONST_RE = re.compile(
    r"\bconst\s+WARD_NODE_PROTOCOL\s*:\s*SupportedProtocolRange\s*=\s*"
    r"SupportedProtocolRange::valid\s*\(([^)]*)\)\s*;"
)
MARKER_RE = re.compile(r"<!--\s*protocol-window:(.*?)-->", re.DOTALL)
WINDOW_RE = re.compile(r"^\s*(\d+)\.(\d+)-(\d+)\.(\d+)\s*$")


class ParseError(Exception):
    """An input that cannot be read as exactly one well-formed range."""


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def code_window(source, path):
    """(major, min_minor, max_minor) from the WARD_NODE_PROTOCOL constant."""
    declarations = CONST_DECL_RE.findall(source)
    if not declarations:
        raise ParseError(f"{path}: no WARD_NODE_PROTOCOL constant found")
    if len(declarations) > 1:
        raise ParseError(f"{path}: malformed: WARD_NODE_PROTOCOL is declared more than once")
    m = CONST_RE.search(source)
    if not m:
        raise ParseError(
            f"{path}: malformed WARD_NODE_PROTOCOL: expected "
            "`SupportedProtocolRange::valid(major, min_minor, max_minor)`"
        )
    args = [a.strip() for a in m.group(1).split(",")]
    if args and args[-1] == "":
        args.pop()  # rustfmt's trailing comma
    if len(args) != 3 or not all(a.isdigit() for a in args):
        raise ParseError(
            f"{path}: malformed WARD_NODE_PROTOCOL arguments {m.group(1).split()}: "
            "expected three integer literals (major, min_minor, max_minor)"
        )
    major, lo, hi = (int(a) for a in args)
    if lo > hi:
        raise ParseError(f"{path}: malformed WARD_NODE_PROTOCOL: min_minor {lo} > max_minor {hi}")
    return major, lo, hi


def doc_window(doc, path):
    """(major, min_minor, max_minor) from the doc's single protocol-window marker."""
    markers = MARKER_RE.findall(doc)
    if not markers:
        raise ParseError(
            f"{path}: no protocol-window marker found; state the window as "
            "`<!-- protocol-window: M.a-M.b -->`"
        )
    if len(markers) > 1:
        raise ParseError(f"{path}: more than one protocol-window marker; keep exactly one")
    raw = markers[0].strip()
    m = WINDOW_RE.match(raw)
    if not m:
        raise ParseError(
            f"{path}: malformed protocol-window marker {raw!r}: expected `M.a-M.b`"
        )
    major_lo, lo, major_hi, hi = (int(g) for g in m.groups())
    if major_lo != major_hi:
        raise ParseError(
            f"{path}: malformed protocol-window marker {raw!r}: a window spans one major"
        )
    if lo > hi:
        raise ParseError(f"{path}: malformed protocol-window marker {raw!r}: inverted range")
    return major_lo, lo, hi


def fmt(window):
    major, lo, hi = window
    return f"{major}.{lo}-{major}.{hi}"


def check(source_path, doc_path):
    """Return (problems, window); an empty problem list means the two agree."""
    problems = []
    code = doc = None
    try:
        code = code_window(read(source_path), source_path)
    except ParseError as err:
        problems.append(str(err))
    try:
        doc = doc_window(read(doc_path), doc_path)
    except ParseError as err:
        problems.append(str(err))
    if code is not None and doc is not None and code != doc:
        problems.append(
            f"code and doc disagree: {source_path} serves {fmt(code)} but {doc_path} "
            f"documents {fmt(doc)}; update the compatibility window (and its per-minor "
            "table and skew policy) in the same change that moves WARD_NODE_PROTOCOL"
        )
    return problems, code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--doc", default=DEFAULT_DOC)
    args = parser.parse_args()

    if args.source == DEFAULT_SOURCE and args.doc == DEFAULT_DOC:
        os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    problems, window = check(args.source, args.doc)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"protocol-window: PASS (code and docs agree on {fmt(window)})")


if __name__ == "__main__":
    main()
