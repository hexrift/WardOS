# Installing WardOS on an existing Linux host

WardOS today is the secure-session layer: three binaries (`ward`, `wardd`,
`ward-agent`) that run on any x86_64 Linux with `bubblewrap`. The immutable host
image (`image/`) is the next step and is documented there.

## 1. One-line install (release binaries)

```bash
curl -fsSL https://raw.githubusercontent.com/hexrift/WardOS/main/install.sh | bash
```

This downloads the latest release tarball, verifies its SHA-256, installs the three
binaries into `~/.local/bin`, and runs `ward doctor`. Use `--prefix /usr/local` for a
system-wide install, `--version v0.1.1` to pin.

No token is needed. For a private fork, export `GITHUB_TOKEN` (or `GH_TOKEN`) with
read access first; the installer then fetches the script's release assets through the
GitHub API with it.

The same script ships inside every release tarball; run `./install.sh` from the
unpacked directory to install from the files next to it.

## 2. Host requirements

| Need | Why | Install |
| --- | --- | --- |
| `bubblewrap` (`bwrap`) | the sandbox | `apt install bubblewrap` · `dnf install bubblewrap` · `pacman -S bubblewrap` |
| unprivileged user namespaces | bwrap without setuid | Ubuntu 24.04+: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`; some distros: `kernel.unprivileged_userns_clone=1` |
| Landlock (kernel ≥ 5.13) | inner file rules in the shim | recommended; without it the shim runs with seccomp only and records the degradation |
| `git` | repository probes, GitHub adapter | usually present |
| a Rust toolchain in `~/.rustup` + `~/.cargo` | `ward verify` on Rust projects | `rustup` (optional) |
| cgroup v2 | nested containers, later | most modern distros (optional today) |

`ward doctor` prints each of these with a fix when it is missing.

## 3. Build from source

```bash
git clone https://github.com/hexrift/WardOS
cd WardOS
cargo build --release -p ward-cli -p ward-daemon -p ward-agent
install -m 0755 target/release/{ward,wardd,ward-agent} ~/.local/bin/
ward doctor
```

The toolchain is pinned in `rust-toolchain.toml`; `rustup` picks it up.

## 4. First session

```bash
cd your-project
ward up                    # policy → manifest, entry snapshot, daemon, log
ward status                # the security panel
ward run -- cargo test     # any command, sandboxed, observed
ward claude                # Claude Code inside the sandbox; key stays on the host
ward watch --tui           # live observer (second terminal)
ward verify                # trusted verifier (needs .tamperward/config.yml)
ward selftest              # 16 hostile probes against your host
ward stop                  # seal the log
```

Put the model-API key in the host environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)
or in `$WARD_STATE_DIR/vault/<NAME>` (mode 0600). For GitHub, set `GITHUB_TOKEN` the same
way and launch with `--grant github`. A project opts into policy with `.ward/policy.yaml`
and into protected tests with `.tamperward/config.yml`; see `examples/ward-demo`.

## 5. Where things live

| Path | Contents |
| --- | --- |
| `~/.local/state/ward` (or `$WARD_STATE_DIR`) | snapshot CAS, session logs, vault |
| `~/.local/state/ward/sessions/<id>/` | `events.log`, `HEAD`, `session.json`, `control.sock` |
| `/tmp/ward-<id tail>/` | per-launch sockets, gone when the command exits |

Keep `WARD_STATE_DIR` short: the control socket path must fit in 107 bytes; `ward
doctor` checks this.

## 6. macOS, ARM, Windows

Linux x86_64 only. On a Mac, run WardOS inside a Linux VM (any distro with bubblewrap).
ARM builds from source but has no release binaries yet.
