# The agents in the image

What the WardOS image ships for the agent-first path of ADR-0017: the two agents `ward`
runs and TamperWard, all from npm, at **exact** versions.

| Package | Command | Pinned |
| --- | --- | --- |
| `@anthropic-ai/claude-code` | `claude` (`ward claude`) | `package.json` |
| `@openai/codex` | `codex` (`ward codex`) | `package.json` |
| `tamperward` | `tamperward` (`ward init` wires it; `tamperward run -- claude`) | `package.json` (2.10.3) |

`package.json` names the three with exact versions (no `^`, no `~`), `private: true`
so it is never published, and `package-lock.json` records every tarball the three
resolve to (the platform packages Claude Code and Codex install as optional
dependencies included, so one lockfile serves x86_64 and aarch64 builds) with its
`integrity` hash. The Containerfile runs `npm ci --omit=dev --ignore-scripts` on this
directory under `/usr/lib/wardos/agents`, `npm rebuild @anthropic-ai/claude-code` for
the one postinstall the build needs, and links the three commands into `/usr/bin`
([`../README.md`, "Agents and TamperWard in the image"](../README.md#agents-and-tamperward-in-the-image)).

## Why exact pins and a lockfile

* **Integrity.** `npm ci` refuses to install anything whose hash differs from the
  lockfile, so the image holds exactly the bytes this repository reviewed, on every
  rebuild, or the build fails. Nothing is fetched at first boot and there is no
  `curl | sh`: an image is complete and works offline.
* **One reviewed diff per bump.** An agent version is a line in `package.json`; the
  change to the lockfile shows every tarball that moved with it.
* **Same versions everywhere.** `ward doctor` prints what is on `PATH`; the image build
  log prints the same three versions ("What the image holds"), so a machine, the
  build and this file agree.

## Bumping a version

```sh
npm view @anthropic-ai/claude-code version           # what is newest
$EDITOR image/agents/package.json                     # set the exact version
cd image/agents && npm install --package-lock-only --ignore-scripts
git add image/agents && git commit                    # both files, one commit
```

Open the pull request; the image build (`image.yml`, "What the image holds") is the
proof: it installs from the new lockfile and runs `claude --version`, `codex --version`
and `tamperward --help` from `/usr/bin`. `npm view <pkg> engines` says which Node the
package needs; the build fails when the image's Node is older than 22, the current
floor (Claude Code's), and `ward doctor`'s `node` row checks the same floor on a host.
Never `npm update` here (it would loosen nothing, but it re-resolves everything), and
never edit the lockfile by hand.
