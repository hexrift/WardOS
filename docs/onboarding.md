# Five minutes to a verified agent

Status: the onboarding path of [ADR-0017](decisions/ADR-0017-agent-first-image.md).
What happens between the first boot (or the one-line install) and the first agent run
that `ward verify` has judged, what the screen shows at each step, and what to do when
something is denied. The commands are the contract; the desktop only wraps them.

```text
boot → welcome → ward vault set → ward init → ward claude → ward verify
```

## 0. Boot, or install

**A machine of its own.** Boot the installer ISO or the disk image
([`image/README.md`](../image/README.md)). tty1 logs in, Hyprland starts, and
`wardos-first-run` copies the default configurations, applies Ward Dark, runs `ward
doctor`, registers the web and terminal apps, shows the keys, runs **CALIBRATE**
(`wardos-calibrate` — language, keyboard layout and timezone, and optionally a login
password; [ADR-0026](decisions/ADR-0026-first-run-calibrate.md)), then opens the welcome.
The default-config copy happens once; CALIBRATE and the welcome are **resumable** — if you
cancel or an apply fails, they are offered again next login (without re-copying your config)
until each is finished, so a half-set-up machine is never left recorded as done. Claude Code
(`claude`), Codex (`codex`), TamperWard (`tamperward`) and `ward` are in the image at pinned
versions; nothing is downloaded at first boot.

**A Linux you already have.** One line installs `ward`, `wardd` and `ward-agent` and
runs `ward doctor` ([`install.md`](install.md) §1); the desktop is optional (§6). The
agents come from their own installers, and TamperWard from `npx tamperward` (Node.js
20.19 or later). The five commands below are the same.

`ward doctor` is the check at any point: each thing the host must give a session, and
the fix when it cannot.

## 1. Welcome (a minute)

`wardos-welcome` runs once at the first login, keyboard-first: every question is a menu
(`wardos-menu-select`, the same picker as the command centre), every step has a Skip,
and Escape skips too.

| Step | What it does | Skip and come back |
| --- | --- | --- |
| Theme | lists `wardos-theme list`, applies your pick | `Super + Shift + T` cycles themes; `wardos-menu style theme` |
| Keys | Anthropic or OpenAI: opens a terminal running `ward vault set NAME`; the key is typed there, never in a menu | `ward vault set NAME` in any terminal |
| Project | a directory picker over `~` (up, into, a typed path, a new directory) or a repository URL to clone; then `ward init` in a terminal that shows its report | `ward init` in any directory |
| Agent | `ward claude` (or `ward codex`) in that project, and one line about the trust bar | `Super + Space` → Start Claude |
| Done | the card: `Super + Space` is everything, `Super + K` lists the keys, this document | — |

The done step writes `~/.config/wardos/welcome-done`. Until it exists, the command
centre (`Super + Space`) opens on `WELCOME  Start here` whenever there is no live
session. Afterwards: Help → Welcome, `wardos-welcome --again`, or one step at a time
(`wardos-welcome keys`).

## 2. The key (`ward vault set`)

```bash
ward vault set ANTHROPIC_API_KEY     # typed without echo; or: … --stdin < file
ward vault list                      # ANTHROPIC_API_KEY set · vault / OPENAI_API_KEY not set / …
```

The key is written to `~/.local/state/ward/vault/ANTHROPIC_API_KEY` (or under
`$WARD_STATE_DIR`), mode 0600 in a 0700 directory, and is never printed back: `list`
says whether a key is set and where, `rm` forgets one, `path` names the directory.
Names are host variables (`[A-Z][A-Z0-9_]*`): `ANTHROPIC_API_KEY` for Claude Code,
`OPENAI_API_KEY` for Codex, `GITHUB_TOKEN` for `--grant github`. A variable of the same
name in the host environment works too and wins over the vault.

Inside the sandbox the agent gets a placeholder and a base URL on the session proxy;
the proxy injects the real key on the way out. That is why a key never has to enter a
project, a shell history or a menu.

## 3. The project (`ward init`)

```bash
cd ~/app
ward init                            # or: ward init ~/app, --agent codex, --dry-run, --no-tamperward
```

```text
WARD init · /home/you/app

  policy      .ward/policy.yaml       written
  gitignore   .gitignore              .ward/sessions/ added
  verifier    .tamperward/config.yml  written (cargo test)
  tamperward  .tamperward.yml         tamperward init ran (its report is above)

Next
  ward claude   start the agent in the sandbox
  ward verify   run the protected tests in the disposable verifier
```

What each line is:

- `.ward/policy.yaml` — what the agent may reach, with a plain-words comment per
  block: `development` network (registries, code hosts, the model API), the repository
  read-write, `github` credentials on `ask` scoped to this repository, the observer
  `live`. Every value is the default; the file exists so the choices are visible and
  reviewable, and a line can only narrow, never widen.
- `.gitignore` — one line for `.ward/sessions/`, added only in a git repository that
  does not ignore it yet.
- `.tamperward/config.yml` — what `ward verify` runs: the protected tests (`tests/`)
  and the command, guessed from `Cargo.toml` (`cargo test`), `package.json` (`npm
  test`) or `pyproject.toml` (`pytest`); without one the key is left commented and
  `ward verify` says so.
- `.tamperward.yml` and the rest of TamperWard's wiring — `tamperward init --cwd .`
  when TamperWard is installed (its own report is printed above ward's: the policy,
  the Claude Code hooks, a pre-commit hook, a CI workflow, all idempotent). Without
  it, a minimal `.tamperward.yml` with the same tests and command, and how to get
  the full wiring.

`ward init` never overwrites a file you wrote: a second run reports `already there,
left as is` for each, so it is safe to run in any directory, any time. The "Next"
block names `ward vault set` only while no key is found.

## 4. The agent (`ward claude`)

```bash
ward claude                          # Codex: ward codex; a one-off: ward run -- cargo test
```

The session starts (the policy becomes a manifest, the worktree is frozen into an
entry snapshot, the log opens), the security panel prints, and Claude Code runs inside
the sandbox as it would anywhere else. The bar at the top of the screen becomes the
trust bar:

```text
● WARD │ sess_01J8ZK3… │ app │ CLAUDE ● working │ NET restricted (dev) │ CRED 0 granted │ OBS live │ TW ✓ │ LIVE
```

Left to right: the mark, the session, the project, the agent and its state (`◌ idle`,
`● working`, `▲ waiting` for you), the network mode, the credentials granted so far,
the observer, TamperWard's protection, and whether the log is live or sealed. Colour
is meaning: green verified, amber restricted, red denied, and only on the marks.

When the agent asks for something the policy marks `ask` (a credential, a paused
write under `step_through`), a notification appears; answer from the keyboard with
`y` (once), `s` (for the session) or `n` (`wardos-approve`), and the agent continues
or is refused. `ward watch` in a second terminal is the same log as a full-screen
observer.

## 5. Verify (`ward verify`)

```bash
ward verify
```

The worktree is snapshotted as a candidate; every protected test and the verify config
are taken from the *entry* snapshot, not the worktree; the command runs offline in a
disposable sandbox; the verdict is recorded in the session log. The bar shows
`VERIFY ◐ 7c01a2b3`, then `VERIFY ✓ 7c01a2b3` (green) or `VERIFY ✗` (red), and the
command exits 0 or 1. The green is bound to that candidate: edit anything afterwards and
the segment reads `VERIFY ~ STALE` (amber) until the next `ward verify`; clicking it shows
the verified candidate, the current digest and how many entries differ.
An agent that weakened a protected test changed nothing the verifier reads, so a
shortcut fails here even when the agent's own run passed.

`ward stop` seals the log (`■ WARD … SEALED`); `ward replay <events.log> --verify`
checks the chain later, anywhere.

## What the bar shows at each step

| Step | The bar |
| --- | --- |
| booted, no session | the mark alone, dim; the shell's text surfaces say `No agent session. Super + Space → Start Claude, or ward init then ward claude in a terminal.` |
| `ward vault set`, `ward init` | unchanged: nothing runs yet |
| `ward claude` | `● WARD │ sess… │ app │ CLAUDE ● working │ NET restricted (dev) │ CRED 0 granted │ OBS live │ TW ✓ │ VERIFY — │ LIVE` |
| an approval pending | `CLAUDE ▲ waiting`, amber, and a notification |
| `--grant github` | `CRED 1 granted` |
| `ward verify` | `VERIFY ◐ 7c01a2b3`, then `VERIFY ✓ 7c01a2b3` green or `VERIFY ✗` red; `VERIFY ~ STALE` amber once the tree changes again (`VERIFY —` before the first run) |
| `ward stop` | `■ WARD … SEALED`, dim |

## When something is denied

Every refusal is a row in the log (`ward watch`, the observer panel) with the subject
and the rule, so the first step is always to read it.

- **`DENY` on a network request.** The host is outside the session's mode:
  `development` reaches package registries, code hosts and the model API, never private
  or cloud-metadata ranges. A project's `.ward/policy.yaml` can narrow the mode but not
  widen it; a host the project genuinely needs is a decision for the host's defaults
  ([`security-model.md`](security-model.md) §3), not for the agent.
- **A credential asked for.** Answer the notification (`y`, `s`, `n`), or launch with
  the grant made up front: `ward claude --grant github` after `ward vault set
  GITHUB_TOKEN`. The token is injected by the proxy on repository-scoped routes; the
  agent never holds it.
- **TamperWard blocked a write** (a protected test, the verify config, a hook, CI). The
  agent is told why in its tool result; the fix is in the implementation, not in the
  judge. `tamperward check` shows the same finding in a terminal; a change that is
  truly wanted is signed off by a person, never by the agent.
- **`ward verify` fails although the agent's tests passed.** The verifier ran the
  protected tests as they were at session start. Compare: `ward snapshot diff <entry>
  <candidate>` names what changed, `ward snapshot cat` shows the pristine file.
- **`ward claude` refuses to start.** `ward doctor`: bubblewrap, user namespaces,
  Landlock, the state directory's path length, the agents, TamperWard and the keys, each
  with its fix.
