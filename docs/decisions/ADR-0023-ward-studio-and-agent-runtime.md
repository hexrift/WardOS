# ADR-0023 — Ward Studio and the Ward Agent Runtime (provider-agnostic agents)

Status: **Proposed / roadmap.** Design the WardOS APIs for it now; build it after WardOS,
Capsules and the Ward APIs are solid. Not a redesign of the desktop; a first-party surface on
top of it.

## Decision
WardOS will ship a first-party agentic development surface, **Ward Studio**, and a
provider-agnostic **Ward Agent Runtime** beneath it. Two invariants define both:

1. **The unit of work is *work*, not the file or the chat thread.** Ward Studio is the loop of
   ADR-0021 made concrete: `intent → plan → Capsule → agent(s) → code/commands/tests →
   TamperWard → evidence → review / commit / undo`. It uses the same interaction vocabulary as
   the desktop — Command Weave, Focus Canvas, Proof Rail, Decision Receipt, BUILD·VERIFY·SHIP
   rooms — and progressively disappears: at rest it is code; files, Git, terminal, symbols,
   agents and even cluster state are reached through Command Weave, not toolbars. Agents
   communicate primarily through **state, artifacts and evidence — prose only when useful**;
   the user reviews results, not thousands of tokens of narration.

2. **The user owns the durable work; the provider supplies intelligence.** WardOS owns intent,
   plan, workspace state, changes, isolation (Capsules, ADR-0022), evidence (TamperWard) and
   recovery. Claude Code, Codex, Gemini, Copilot, local models and custom ACP/MCP agents are
   **replaceable brains** behind a thin adapter. Each adapter implements one capability model
   (`authenticate · status · start_task · resume_task · cancel_task · stream_events ·
   request_permission · read_changes · tool_calls · usage · disconnect`) and normalises
   provider events into one `AgentEvent` vocabulary (`thinking · planning · reading · editing ·
   executing · requesting_permission · testing · waiting · completed · failed`) so the Proof
   Rail renders every agent identically. Provider quirks never leak into the UI.

**Every agent gets its own computer.** Because the editor and OS cooperate, parallel agents
each run in their own Capsule (own worktree, own secrets/network policy), and a fresh Capsule
runs the independent verifier — the WardOS distinction over cloud-only isolated agents.

**Agent Accounts.** Connecting an agent must feel like signing into a service, not integrating
a toolchain: *discover → authenticate → use*. An Agent Accounts service tracks connection,
token expiry/refresh, CLI state, identity and scope; detects an existing `claude`/`codex` CLI
login and offers to reuse it (no competing auth worlds); and translates auth failures into
human-readable prompts ("Claude needs you to sign in again. Your current work is safe.
[Reconnect]") that resume the task where it stopped. Existing provider CLI workflows keep
working unchanged — Ward Studio is an integration layer, not a prison.

**Hand-off and recovery are first-class.** On usage limits, crashes, network loss or token
expiry, the task's structured state (intent/plan/workspace/changes/evidence/history) is
preserved and can continue on another agent or resume on the same one — the user does not
copy-paste conversations or babysit agents. Invariant: **a provider failure must never become
a workspace failure**; agents operate behind Capsule/worktree transactional boundaries.

**Performance is a product requirement** (native, GPU-rendered, Rust; LSP/DAP/Tree-sitter;
native Git/terminal; incremental indexing; lazy extensions): cold launch < 500 ms aspirational,
warm effectively instant, typing latency < 10 ms, command response < 100 ms, workspace switch
< 150 ms perceived, 60 fps floor / 120 Hz optimised. No Electron unless engineering reality
later shows the ecosystem benefit outweighs these.

**Never demand ecosystem sacrifice.** Support LSP, DAP, Tree-sitter, ACP, MCP, devcontainers,
Docker/Compose, SSH, Git, GitHub/GitLab and standard formatters/debuggers directly; keep
VS Code, JetBrains, Zed, Neovim and Emacs first-class WardOS citizens. **Ward Studio wins
usage, it does not enforce it.** Reusable components/ideas may be borrowed (e.g. Apache-2.0
pieces) but WardOS does not fork an existing editor wholesale — that would recreate the
identity problem ADR-0021 exists to avoid.

Reliability SLO-style targets: agent connection success > 99.9%; reconnect without task loss
> 99.9%; task-start UI acknowledgement < 500 ms; auth status check < 1 s; UI event delivery
< 100 ms after receipt; a provider or agent crash never crashes Ward Studio or loses the
workspace.

## Context
By 2026 native/external agents, parallel agent threads, worktree isolation, tool-permission
config, MCP/ACP, and cloud isolated-VM agents with evidence are becoming table stakes (Zed,
Cursor). WardOS's opportunity is one layer deeper: it controls the OS, so it can hand any
agent a local, policy-driven disposable computer (ADR-0022) and independently verify the
result (TamperWard) rather than trusting a green checkmark. The strategic risk is building
"another editor with an AI sidebar", or coupling to one model vendor. Fixing the ownership
split (WardOS owns work/state/isolation/evidence; providers supply intelligence) and a
provider-agnostic runtime now protects WardOS from any single model's year-to-year fortunes
and from provider auth/protocol churn.

## Consequences
* The Ward Capsule API (ADR-0022) and the daemon control plane (ADR-0015) are designed with
  Ward Studio as a first consumer: parallel per-agent Capsules, structured task state, and an
  event stream the Proof Rail consumes.
* A `Ward Agent Runtime` with per-provider adapters and an `Agent Accounts` service is added to
  the roadmap; the existing gateway credential model (ADR-0008) informs how provider secrets
  stay off the agent.
* Sequencing (does not block reliability/onboarding/discoverability): **WardOS solid →
  Capsules + Ward APIs → thin Ward Studio prototype → agent orchestration + proof → mature
  editor capabilities.** The first prototype deliberately supports only TypeScript/Python/Rust
  + terminal + Git + LSP + Claude/Codex + Capsules + TamperWard; it expands only if that
  experience is exceptional.
* No editor is forked wholesale; other editors remain first-class, so WardOS does not strand
  existing developer workflows.

## Alternatives considered
* **Fork Zed (or VS Code) into "Ward Zed".** Fast to a visual result, but most of Zed's app is
  GPL-3.0-or-later and a wholesale fork would make Ward Studio permanently "Zed with WardOS
  integration" — the identity trap ADR-0021 rejects. Borrow reusable Apache-2.0 pieces/ideas
  instead.
* **Bless one agent vendor (Claude-only).** Simpler adapters, but couples WardOS to one model's
  fortunes and to its auth/protocol changes; the provider-agnostic runtime is the strategic
  hedge and a better user experience (switch agents without changing workflow).
* **Electron for ecosystem reach.** Contradicts the latency/perf requirements that make an
  agentic IDE feel native; revisit only if the ecosystem benefit is later shown to outweigh.
* **Do nothing / stay CLI-only (`ward claude`).** Leaves the agentic review/evidence/isolation
  experience to third-party IDEs that cannot offer local policy-driven Capsules + independent
  verification — forfeiting WardOS's actual moat.

## How it will be validated
* First-run connects an agent in *discover → authenticate → use* with no manual env-var/key
  hunting; an existing `claude`/`codex` CLI login is detected and reusable.
* An agent or provider crash mid-task preserves the workspace and offers resume/hand-off with
  structured state (not conversation copy-paste); reconnect resumes where it stopped.
* Two agents run in parallel, each in its own Capsule/worktree, and a third fresh Capsule
  verifies — with the Proof Rail rendering all three through one `AgentEvent` vocabulary.
* Editor latency/launch targets are met on ordinary hardware; VS Code/JetBrains/Zed/Neovim
  remain usable against the same project unchanged.
