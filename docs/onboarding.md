# Five minutes to a verified agent

Status: the onboarding path of [ADR-0017](decisions/ADR-0017-agent-first-image.md).
What happens between the first boot (or the one-line install) and the first agent run
that `ward verify` has judged, what the screen shows at each step, and what to do when
something is denied. The commands are the contract; the desktop only wraps them.

```text
boot → welcome → ward vault set → ward init → ward prepare → ward claude → ward verify
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
| Project | a directory picker over `~` (up, into, a typed path, a new directory) or a repository URL to clone; then `ward init` in a terminal that shows its report and, when the project's files propose one verification boundary, asks whether to accept it | `ward init` in any directory |
| Agent | `ward ready` checks the project first; a blocking gap shows its report and asks before continuing (`Fix it first` opens `ward init` in a terminal, where a proposed-but-unaccepted verification boundary is accepted); then `ward claude` (or `ward codex`) there, and one line about the trust bar | `Super + Space` → Start Claude |
| Done | the card: `Super + Space` is everything, `Super + K` lists the keys, `Super + Shift + Escape` (or `POWER` in the bar) locks, suspends or shuts down, this document | — |

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
ward init                            # or: ward init ~/app, --accept-verify, --agent codex, --dry-run, --no-tamperward
```

```text
WARD init · /home/you/app

  policy      .ward/policy.yaml       written
  gitignore   .gitignore              .ward/sessions/ added
  verifier    .tamperward/config.yml  written (proposed, not accepted: cargo test --locked)
  tamperward  .tamperward.yml         tamperward init ran (its report is above)

Proposed verification boundary, from the project's files (nothing was run)
  command     cargo test --locked  Cargo.toml · Cargo.lock
  protected   tests/               cargo integration tests directory
  read-only   Cargo.toml           manifest
              Cargo.lock           lockfile: pins the dependency set `--locked` checks
  not accepted: written commented out; nothing runs until a trusted user accepts it with `ward init --accept-verify`

Next
  ward init --accept-verify   accept the proposed verification boundary; nothing is verified before
  ward prepare                install the dependency set the lockfile pins, once, online, for the verifier
  ward claude                 start the agent in the sandbox
  ward verify                 run the protected tests in the disposable verifier
```

In a terminal, `ward init` asks the question itself (`Accept this verification
boundary? [y/N]`) when exactly one boundary is proposed; `y` writes it active, anything
else leaves it as above. `--accept-verify` is the same yes for a script.

What each line is:

- `.ward/policy.yaml` — what the agent may reach, with a plain-words comment per
  block: `development` network (registries, code hosts, the model API), the repository
  read-write, `github` credentials on `ask` scoped to this repository, the observer
  `live`. Every value is the default; the file exists so the choices are visible and
  reviewable, and a line can only narrow, never widen.
- `.gitignore` — one line for `.ward/sessions/`, added only in a git repository that
  does not ignore it yet.
- `.tamperward/config.yml` — what `ward verify` runs: the protected inputs and the
  command, proposed from the project's own files and shown with the evidence for each
  (issue #147 item 2). The command: `Cargo.toml` (`cargo test`, `--locked` with a
  `Cargo.lock`, `--workspace` for a `[workspace]`), a `package.json` `test` script run
  by the package manager its lockfile names (`pnpm test`, `yarn test`, `npm test`),
  pytest configuration or a pytest dependency (`pytest`), `go.mod` (`go test ./...`)
  or a Makefile `test` target (`make test`). The protected inputs, restored from the
  entry snapshot: `tests/` and every `[[test]]` path of a Cargo package and of each
  workspace member; a Node project's `test/`, `tests/`, `__tests__/`, `spec/` and
  runner configuration (`jest.config.*`, `vitest.config.*`, `.mocharc.*`, …); pytest's
  configured `testpaths` wherever they are (so tests outside `tests/` are protected
  and `tests/` is never assumed), the file holding the pytest section and
  `conftest.py`. The read-only inputs, which the verifier reads and never rewrites:
  the manifest and the lockfile (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`,
  `yarn.lock`, `poetry.lock`, `uv.lock`, `requirements*.txt`, `go.sum`); a missing
  lockfile is named as a gap, not papered over. Nothing is executed to decide, and
  nothing is accepted for you: the boundary is written active only on `--accept-verify`
  or a yes at the terminal; otherwise it is written commented out and `ward ready`
  reports `verification command not accepted` with the same proposal. A
  `package.json` without a real `test` script, a bare `pyproject.toml` or a directory
  with no manifest is `cannot propose: <why>`, never a default guess; when several
  commands match, all are written commented, none is chosen, and `--accept-verify`
  refuses to pick. `ward ready --propose` prints the proposal again for an existing
  project and changes nothing.
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

## 5. Prepare dependencies (`ward prepare`)

```bash
ward ready                           # dependencies: never prepared; `ward prepare` installs …
ward prepare                         # once, online; --rebuild discards and installs again
```

The verifier is offline (ADR-0004), so a Node or Python project's dependency set has to
exist before `ward verify` can run its tests. `ward prepare` is the one explicit phase
that fetches anything (issue #147 items 3, 4 and 6). It reads the lockfile and the
manifest beside it (`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml` or
`yarn.lock` with `package.json`, plus `.npmrc` when present; `requirements*.txt`), runs
the manager's install for exactly that lockfile with no scripts — `npm ci
--ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts`, `yarn install
--frozen-lockfile --ignore-scripts`, `python3 -m pip install --target` — inside the
same bubblewrap sandbox and toolchain view the verifier uses, with one difference: the
launch asks for the host's network namespace, and only for this phase. The project is
not mounted at all; the install sees a copy of its inputs and writes only into the
environment's own directory under the state root, `<state>/prepared/<key>/stage/`,
which is sealed read-only on success. Progress (elapsed time, files, bytes) streams to
stderr about once a second; the panel afterwards shows the inputs and their digests,
the runtime and platform, the command, the network note, where the environment is and
the cold timing.

`<key>` is a digest over the ecosystem and manager, the content digests of the inputs,
the runtime's `--version` as the *verifier* would run it (`node`, `python3`, resolved in
the verifier's own search directories, never your shell's `PATH`), the platform
(architecture, libc, OS release) and the configured registry (`NPM_CONFIG_REGISTRY`,
`PIP_INDEX_URL`). Change any of them and the environment is a different key: the old
one is left untouched and `ward ready`'s `dependencies` row reads `stale:
package-lock.json changed since 63080ebb75af was prepared` (or `runtime changed (node
v22.0.0 → v24.0.0)`, `platform changed`), each ending in "run `ward prepare`", and the
verdict is `setup required` until you prepare again. The same row says `never
prepared`, `incomplete: attempt 1 … did not finish` (the installer was killed or ran
past its 30-minute budget) or `failed: attempt 1 … exited 1` (its output is kept in
`prepared.json` and printed), and once ready `prepared 63080ebb75af (node-npm) · warm
1 ms · cold 41.2 s on 2026-10-05` — the warm figure is this lookup, the cold one the
recorded install. An incomplete or failed environment is never mounted; the next `ward
prepare` removes its partial tree, starts from scratch and counts the attempt. A second
`ward prepare` on unchanged inputs answers `already prepared · warm <1 ms`.

Three things `ward prepare` refuses to guess: it runs nothing until the verification
boundary is accepted (`ward init --accept-verify`); a `package.json` without a lockfile,
or a Python project with only `poetry.lock`, `uv.lock` or `Pipfile.lock`, is
`cannot prepare: <why>` and the row reads `FAIL` with the same reason (export to
`requirements.txt` to prepare from); and a Cargo project needs no environment at all —
the verifier already mounts the host's `~/.cargo/registry` read-only and `cargo test
--locked` resolves offline from it — so the row is `OK none to prepare: cargo: …`.

## 6. Verify (`ward verify`)

```bash
ward verify
```

The worktree is snapshotted as a candidate; every protected test and the verify config
are taken from the *entry* snapshot, not the worktree; the command runs offline in a
disposable sandbox, with the prepared dependency environment whose key matches the
candidate's own lockfile mounted read-only beside it (`node_modules` at
`/work/node_modules`; a Python target directory under `/run/verifier/deps`, named by
`PYTHONPATH`, its `bin` first on `PATH`) — the report and the log carry a
`dependencies` line saying what was mounted, or why nothing was (`not mounted: stale:
…`), and the verifier fetches nothing either way; the verdict is recorded in the
session log. The bar shows
`VERIFY ◐ 7c01a2b3`, then `VERIFY ✓ 7c01a2b3` (green) or `VERIFY ✗` (red), and the
command exits 0 or 1. The green is bound to that candidate: edit anything afterwards and
the segment reads `VERIFY ~ STALE` (amber) until the next `ward verify`; clicking it shows
the verified candidate, the current digest and how many entries differ.
An agent that weakened a protected test changed nothing the verifier reads, so a
shortcut fails here even when the agent's own run passed.

`ward stop` ends the agent's sandboxed processes, confirms they are gone, and then
seals the log (`■ WARD … SEALED`); `ward replay <events.log> --verify`
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
- **`ward verify` cannot find a module or a test runner.** The verifier is offline and
  mounts only a prepared environment whose key matches the candidate's lockfile; its
  `dependencies` line says why none was (`never prepared`, `stale: package-lock.json
  changed`, `incomplete`). `ward prepare` is the fix, and the only place a fetch happens
  (§5).
- **`ward claude` refuses to start.** `ward doctor`: bubblewrap, user namespaces,
  Landlock, the state directory's path length, the agents, TamperWard and the keys, each
  with its fix.
