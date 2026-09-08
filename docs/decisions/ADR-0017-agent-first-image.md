# ADR-0017 — Agent-first: the agents, TamperWard and a first-run path ship in the image

## Decision
A WardOS install is useful the minute it boots, without installing anything: the image
carries the agents it exists to run (Claude Code and OpenAI Codex), TamperWard, and a
Node.js runtime for them, all at pinned versions installed at build time with npm's
integrity checks, never fetched by the user. `ward init` makes any directory a project
in one command (policy, TamperWard wiring, first snapshot); `ward vault` keeps API keys
on the host where the proxy injects them; `wardos-welcome` walks a first login through
theme, keys, first project and first agent in under five minutes, and the command centre
and the shell say what to do next whenever there is no session. `ward doctor` reports the
agents, TamperWard and the keys as it reports the kernel features.

Security posture ships on too: the installer ISO encrypts the disk unless told not to,
the host firewall admits nothing inbound by default, and the image updates itself from
the published registry image on a timer, with the previous deployment kept for rollback.

## Alternatives
- Install agents at first run (`npm install -g`). Rejected: a first boot that downloads
  unpinned code is neither easy nor security-conscious, and offline machines get nothing.
- Ship only WardOS's own tools and let users bring agents. Rejected: the product is
  agent-first; an image without agents is a sandbox with nothing to sandbox.
- A separate "agents" container. Deferred: the sandbox already binds `/opt` read-only,
  so host-installed agents are the simplest path; an OCI-delivered agents layer can
  replace it without changing the user's experience.

## Advantages
- Zero-install onboarding: boot, pick a theme, paste a key, `ward init`, `ward claude`.
- Every agent version is a line in `image/agents/package.json` with a lockfile, checked
  by the image build; an update is a reviewed pull request, never a `curl | sh`.
- TamperWard is a first-class tool: `ward init` wires its policy and hooks, `ward verify`
  and `tamperward verify` agree on what is protected.

## Disadvantages
- Node.js adds about 60 MB to the image; the agents add more. Accepted for the product's
  purpose; the size issues (#67–#70) still apply elsewhere.
- Agent releases move fast; a pinned version lags upstream by design. `wardos-update`
  follows the image, and a bump is a small pull request.

## Security consequences
- Agents are under `/opt/wardos/agents`, root-owned, read-only in the sandbox; the user
  cannot alter them and neither can an agent.
- Keys live in `$WARD_STATE_DIR/vault` (mode 0600) and never enter the sandbox; the
  vault command refuses to print a stored key back.
- LUKS by default, an inbound-deny firewall, and timed image updates close the three most
  common gaps of a freshly installed workstation.

## Performance consequences
None at run time; the image build gains an `npm ci` step (about a minute).

## Why selected
The eight properties the product is held to (simple, useful, better look and feel,
lightweight, portable, easy to set up, clear onboarding, agent-first, security-conscious,
TamperWard included) are all served by the same move: put the agent toolchain and the
first-run path into the image and make one command out of each step.

## How it will be validated
The image build installs the agents and `ward doctor` reports them; the desktop test
suite covers `wardos-welcome`; `ward init` has unit and e2e tests; E-09 walks the
onboarding on real hardware and records the time from boot to a verified agent run.
