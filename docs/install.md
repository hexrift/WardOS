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
system-wide install, `--version v0.2.0` to pin.

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
on tty1, `uwsm` starts Hyprland, `wardos-first-run` copies the configs and asks for a
theme, and Flathub plus `desktop/flatpaks.txt` arrive in the background. Updates:
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

The tools are Linux x86_64 only: the sandbox (bubblewrap, namespaces, Landlock,
seccomp) has no macOS or Windows equivalent. ARM builds from source but has no release
binaries yet.

On a Mac, run the whole OS in a VM. Do not try to build the disk there: download it from
CI instead (the `disk` workflow's artifact, or the `.qcow2.zst` attached to a release;
see [`image/README.md`](../image/README.md), "Disk images from CI"), then boot it in UTM
as an x86_64 machine. On Apple silicon that is emulated and slow but works; an Intel Mac
runs it natively. Docker Desktop can build and inspect the container image
(`--platform linux/amd64`) but cannot produce a bootable disk. A native Apple-silicon
image needs aarch64 builds of the Hyprland COPRs; the `disk` workflow's `aarch64
chroots` job reports whether they exist.
