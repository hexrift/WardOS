# Installing WardOS on an existing Linux host

WardOS today is the secure-session layer: three binaries (`ward`, `wardd`,
`ward-agent`) that run on any x86_64 Linux with `bubblewrap`. The immutable host
image (`image/`) is the next step and is documented there.

## 1. Install the release binaries

Every release attaches one tarball per architecture and its checksum:
`wardos-<version>-<arch>-linux.tar.gz` and `wardos-<version>-<arch>-linux.tar.gz.sha256`,
where `<arch>` is what `uname -m` prints (`x86_64`; `aarch64` from v0.3). Download both
from the [latest release](https://github.com/hexrift/WardOS/releases/latest), check
the tarball before unpacking it, and copy the binaries into your path:

```bash
sha256sum -c wardos-0.2.0-x86_64-linux.tar.gz.sha256       # "OK", or stop here
tar -xzf wardos-0.2.0-x86_64-linux.tar.gz
cp wardos-0.2.0-x86_64-linux/{ward,wardd,ward-agent} ~/.local/bin/
ward doctor
```

The tarball also carries `ward-shell` and `wardos-theme-render` (the desktop's
binaries, only useful with the desktop of §6) and a copy of `install.sh`. The checksum
proves the tarball is the one CI attached to the release; releases are not yet signed,
which is a signing-key decision recorded in [`roadmap.md`](roadmap.md).

**The OS image** is the other way in: on a machine of its own, boot it and the tools,
the agents, TamperWard and the desktop are already there (§6, [`image/README.md`](../image/README.md)).

**The convenient development installer.** The same three steps, done by a script:

```bash
curl -fsSL https://raw.githubusercontent.com/hexrift/WardOS/main/install.sh | bash
```

It resolves the latest release, downloads the tarball for this machine's architecture,
verifies its SHA-256 against the `.sha256` from the same release, installs the three
binaries into `~/.local/bin`, and runs `ward doctor`. Use `--prefix /usr/local` for a
system-wide install, `--version v0.2.0` to pin. It is a script fetched from `main` and
run unread, which is why it is not the headline: read it, or run `./install.sh` from
an unpacked tarball, where it installs the files next to it and fetches nothing.

No token is needed. For a private fork, export `GITHUB_TOKEN` (or `GH_TOKEN`) with
read access first; the installer then fetches the release assets through the GitHub
API with it.

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

## 4. First project, first session

Three commands from a fresh install to an agent inside the sandbox, and one more to a
verdict ([`onboarding.md`](onboarding.md) is the same path with the desktop):

```bash
ward vault set ANTHROPIC_API_KEY   # typed without echo; stored 0600 on the host, never printed back
cd your-project
ward init                          # .ward/policy.yaml, .tamperward/config.yml, .gitignore, TamperWard
ward claude                        # Claude Code inside the sandbox; the proxy injects the key
ward verify                        # the protected tests, from the entry snapshot, offline
```

`ward init [DIR]` makes a directory a project and is safe to repeat: it writes only what
is absent, never a file you wrote, and reports each item (`written`, `already there,
left as is`). The policy it writes is the secure default with a comment per block, so
the file reads as a description of what the agent gets; the verifier config names the
protected tests (`tests/`) and a command guessed from `Cargo.toml`, `package.json` or
`pyproject.toml`; when `tamperward` is installed, `tamperward init --cwd DIR` wires
its policy, the Claude Code hooks, a pre-commit hook and a CI workflow (`--no-tamperward`
leaves that alone), and without it a minimal `.tamperward.yml` is written and the
report says how to get the rest. `--agent codex` names Codex and its key in the closing
"next" block; `--dry-run` prints the plan and touches nothing.

Keys live in `$WARD_STATE_DIR/vault/<NAME>` (`ward vault set|list|rm|path`; names are
host variables, `[A-Z][A-Z0-9_]*`) or in the host environment, which wins. Inside the
sandbox the agent sees a placeholder and a base URL on the session proxy. For GitHub,
`ward vault set GITHUB_TOKEN` and launch with `--grant github`: the token is injected on
repository-scoped routes.

The longer form, one step at a time:

```bash
ward up                    # policy → manifest, entry snapshot, daemon, log
ward status                # the security panel
ward run -- cargo test     # any command, sandboxed, observed
ward watch --tui           # live observer (second terminal)
ward selftest              # 16 hostile probes against your host
ward stop                  # seal the log
```

`examples/ward-demo` is a project with a protected test and a tempting shortcut, for
seeing `ward verify` refuse one.

## 5. Where things live

| Path | Contents |
| --- | --- |
| `~/.local/state/ward` (or `$WARD_STATE_DIR`) | snapshot CAS, session logs, vault |
| `~/.local/state/ward/sessions/<id>/` | `events.log`, `HEAD`, `session.json`, `control.sock` |
| `~/.local/state/ward/vault/<NAME>` | one key per file, 0600 in a 0700 directory (`ward vault`) |
| `<project>/.ward/policy.yaml`, `.tamperward/config.yml`, `.tamperward.yml` | the project's policy, verifier config and TamperWard policy (`ward init`) |
| `/tmp/ward-<id tail>/` | per-launch sockets, gone when the command exits |

Keep `WARD_STATE_DIR` short: the control socket path must fit in 107 bytes; `ward
doctor` checks this.

## 6. Desktop

The WardOS desktop ([`desktop.md`](desktop.md), ADR-0016) comes two ways.

**The OS image.** A Fedora bootc image with everything in it: build it and make a disk
on a Fedora host with podman ([`image/README.md`](../image/README.md)):

```bash
sudo ./image/build.sh                                            # the image
sudo ./image/disk.sh --type iso --user wardos --luks             # installer ISO, encrypted disk
sudo ./image/disk.sh --type qcow2 --user wardos --password …     # or a VM disk
```

`--user wardos` creates the first user (wheel), which the tty1 autologin expects; with
`--luks` Anaconda asks for the passphrase during the installation. First boot logs in
on tty1, `uwsm` starts Hyprland, `wardos-first-run` copies the configs and hands over
to `wardos-welcome` (theme, key, first project, first agent; [`onboarding.md`](onboarding.md)),
and Flathub plus `desktop/flatpaks.txt` arrive in the background. Updates:
`wardos-update` (`bootc upgrade`; the previous deployment stays, `bootc rollback`).

**On a Fedora you already have** (44, the release the image pins: Workstation, Silverblue, Kinoite):

```bash
git clone https://github.com/hexrift/WardOS && cd WardOS
./desktop/install.sh --dry-run     # every command it would run
./desktop/install.sh               # packages (dnf, or rpm-ostree + reboot), the tree, units, Flathub
```

It enables the COPRs of `image/coprs.txt` (the Hyprland ecosystem Fedora does not
package, lazygit), installs `image/packages.txt`, places the tree with `image/install-desktop.sh` under
`/usr/share/wardos` and `/etc/xdg` (sudo, per step), enables the user units, adds
Flathub and the default applications, and prints how to log in: pick "Hyprland (uwsm)"
at GDM or SDDM, or `uwsm start hyprland.desktop` from a console. It does not install
the tty1 autologin unless told `--autologin`, and never touches your `~/.config`:
that is `wardos-first-run`'s job, with a backup next to anything it replaces.

## 7. macOS, ARM, Windows

The tools are Linux only: the sandbox (bubblewrap, namespaces, Landlock, seccomp) has
no macOS or Windows equivalent. They come for two architectures, x86_64 and, from
v0.3, aarch64; `install.sh` picks the tarball by `uname -m`, and the image and its
disks exist for both ([`image/README.md`](../image/README.md), "aarch64 and Apple
silicon").

**Apple-silicon Mac (M1 and later).** Run the whole OS in a VM, natively: download the
aarch64 qcow2 (the `disk` workflow's `wardos-disks-aarch64` artifact, or the
`wardos-<version>-aarch64.qcow2.zst` attached to a release; `zstd -d` restores it) and
boot it in [UTM](https://mac.getutm.app) as a Linux virtual machine with the Apple
Virtualization backend: "Use Apple Virtualization", UEFI boot, 4 GB of memory, 4 cores,
the qcow2 attached as a virtio disk, the display on virtio-gpu. The UTM settings and
the caveats (no Secure Boot, screen scaling) are in the README section above. Do not
try to build the disk on the Mac: bootc-image-builder needs a privileged Linux podman
with loop devices, which Docker Desktop's VM does not provide; CI builds it on an
arm64 runner. Docker Desktop can build and inspect the *container* image
(`docker build --platform linux/arm64 …`) for a look around.

**Intel Mac.** The same, with the x86_64 qcow2 (`wardos-<version>-x86_64.qcow2.zst`)
and UTM's QEMU backend (the Apple Virtualization backend on Intel boots it too); it
runs natively. An aarch64 disk on an Intel Mac, or an x86_64 one on Apple silicon, is
emulated: it boots, slowly; use the disk of your own architecture.

**Windows.** The tools only, in WSL2: an Ubuntu 24.04 distribution installs the release
binaries as in §1 (bubblewrap and unprivileged user namespaces work in WSL2's kernel;
`ward doctor` says so), and `ward` sandboxes agents there. The desktop and the OS image
do not run under WSL2; a Hyper-V machine could boot the x86_64 disk (`qemu-img convert
-O vhdx` the qcow2, Generation 2, Secure Boot off) but that path is untested.
