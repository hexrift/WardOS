# AI-agent repository rules

These rules apply to every agent and every GitHub-facing action in this repository.

- Do not add model/tool attribution to commit messages, pull requests, issues, reviews,
  comments, branch names, code comments, or files.
- Do not publish AI session/deep links or session identifiers on any public repository surface.
- Use the repository author's configured Git identity. Do not add an assistant as a co-author.
- Before any GitHub write, strip tool-generated attribution and session metadata from the text.
- The shared Claude settings disable commit/PR attribution at source. Repository automation is
  defense in depth: the required verify job rejects attribution/session metadata in mergeable
  content, and a separate sanitizer removes it from PR/issue discussion surfaces.
