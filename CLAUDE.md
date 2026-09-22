# AI-agent repository rules

These rules apply to every agent and every GitHub-facing action taken in this repository.

- Do not add model or tool attribution to commit messages, pull requests, issues, reviews,
  comments, branch names, code comments, or any tracked file.
- Do not publish an AI session link, session identifier, or other session metadata on any
  repository surface that is or could become public.
- Use the repository author's own configured Git identity for commits. Do not add an
  assistant as a co-author.
- Before any GitHub write (commit, push, PR, issue, comment, review), strip tool-generated
  attribution or session metadata from the text first, rather than relying on the layers
  below to catch it.

This is defense in depth, not one single check: `.claude/settings.json` disables
commit/PR attribution at the tool level; `scripts/verify/no-agent-attribution.sh`, wired
into the required `verify` workflow, fails a pull request whose title, body, or added
commits still carry it; `.github/workflows/sanitize-agent-attribution.yml` strips it after
the fact from PR/issue bodies and comments if it slips through anyway.

See issue #204 for the history of this decision, and
[`docs/development-under-tamperward.md`](docs/development-under-tamperward.md) for how this
sits alongside TamperWard's other protected-surface rules.
