# WardOS host image

The Fedora **bootc** image that is the WardOS host (ADR-0001, [`architecture.md` §12](../docs/architecture.md)),
with the desktop of [ADR-0016](../docs/decisions/ADR-0016-desktop-feature-set.md) in it.
This directory is Phase 6 of the [roadmap](../docs/roadmap.md), started: the image is
authored, lint-checked, package-checked and built in CI, and it has **not yet been
booted** on real hardware. Experiment E-09 ([`experiments.md`](../docs/experiments.md))
is the validation; until it is recorded, treat every "boots", "enrols", "rolls back"
below as a plan, and every line marked *unverified* as the first suspects when it does
not.

## Layout

| Path | Ships as | Purpose |
| --- | --- | --- |
| `Containerfile` | the image | Build or fetch the ward binaries; layer packages, binaries, desktop and configuration on `fedora-bootc` |
| `packages.txt` | — | Every package the host installs, one per line with the reason; the Containerfile and `desktop/install.sh` read it |
| `coprs.txt` | `/etc/yum.repos.d/_copr:*.repo` | The COPR repositories enabled before the install (Hyprland's ecosystem, lazygit); part of the trust set |
| `check-packages.sh` | — | Proves every name in `packages.txt` exists in the pinned Fedora release plus `coprs.txt` (`dnf repoquery` in a `fedora:<release>` container); CI job "image packages" |
| `install-desktop.sh` | — | Places `desktop/` into a root (`/` in the build, `/` from `desktop/install.sh`, a temp dir in tests) |
| `agents/package.json`, `agents/package-lock.json` | `/usr/lib/wardos/agents/`, then `node_modules/` from `npm ci`; `/usr/bin/{claude,codex,tamperward}` | Claude Code, Codex and TamperWard at exact versions (ADR-0017; [`agents/README.md`](agents/README.md)) |
| `rootfs/usr/libexec/wardos-flathub` | `/usr/libexec/wardos-flathub` | Adds Flathub and installs `desktop/flatpaks.txt`, run once by `wardos-flathub.service` |
| `build.sh` | — | `podman build` wrapper; tags `localhost/wardos:<git describe>` and stamps the version label; `--arch x86_64|aarch64` |
| `disk.sh` | — | `bootc-image-builder` wrapper; qcow2 for QEMU, ISO for installation (encrypted unless `--no-luks`); `--user`, `--arch` |
| `sysctl.d/50-wardos.conf` | `/usr/lib/sysctl.d/` | Unprivileged user namespaces for `wardd`'s sandboxes |
| `tmpfiles.d/wardos.conf` | `/usr/lib/tmpfiles.d/` | Creates `/var/lib/wardos` at boot |
| `systemd/wardos-firstboot.service` | `/usr/lib/systemd/system/` | Runs `ward doctor` once, keeps the report |
| `systemd/wardos-flathub.service` | `/usr/lib/systemd/system/` | Flathub remote and default applications, once, after the first boot with a network |
| `rootfs/usr/lib/systemd/system-preset/90-wardos.preset` | `/usr/lib/systemd/system-preset/` | The system units the image enables: the two above, `firewalld.service`, `bootc-fetch-apply-updates.timer` |
| `rootfs/usr/lib/systemd/system/bootc-fetch-apply-updates.service.d/wardos.conf` | `/usr/lib/systemd/system/…/` | The update timer stages the next image and never reboots |
| `rootfs/etc/firewalld/zones/wardos.xml` | `/etc/firewalld/zones/` | The default zone: nothing inbound |
| `plymouth/wardos/` | `/usr/share/plymouth/themes/wardos/` | The boot splash: WARD on the ground colour |
| `boot/` | (plan) | How the image boots, updates and rolls back; UKI/systemd-boot plan |
| `secure-boot/` | (plan, CODEOWNERS) | Secure Boot chain and what signing would need |
| `keys/` | (plan, CODEOWNERS) | Public verification keys only; the rule that private material never enters the repo |

`../.containerignore` (mirrored as `.dockerignore`) keeps the build context to the Rust
workspace, `image/` and `desktop/` (minus its tests); `../.hadolint.yaml` disables one
hadolint rule, explained inside.

## What is in the image

Stage 1 provides the ward binaries, from a release tarball or a build of this checkout
([below](#where-the-binaries-come-from)). Stage 2 starts from
`quay.io/fedora/fedora-bootc:44` and installs every package of
[`packages.txt`](packages.txt): the runtime set (`bubblewrap git curl python3
openssh-clients rustup podman`, reasons in the file and in the next paragraph), the
English locale, the Hyprland stack, the components that render the shell's surfaces
until E-10 (Waybar, fuzzel, mako, swayosd), capture tools, audio, Bluetooth, Wi-Fi,
power, fingerprint and FIDO2, printing, terminals and TUIs, Chromium, Nautilus,
Flatpak, podman and friends, the fonts the desktop renders, icon and GTK themes, and
Plymouth. What is *not* there, and why, is the [Size](#size) section: one browser
(Firefox is `wardos-install app org.mozilla.firefox`), no compiler, no other locales.

On the runtime set: `bubblewrap` is the sandbox builder (ADR-0002, ADR-0013); `git` and
`openssh-clients` serve worktrees, snapshots (ADR-0010) and git over ssh through the
broker; `curl` and `python3` the self-checks, `scripts/security-check` and hook
adapters; `podman` nested containers inside project environments (ADR-0005). `rustup`
is Fedora's package of the installer only (`rustup-init`), not a toolchain: ADR-0001
keeps compilers off the host, and the trusted verifier
([`verify.rs`](../crates/ward-daemon/src/verify.rs)) binds a Rust toolchain read-only
into Zone 2 from the *user's* `~/.rustup` and `~/.cargo`, which is where
`Toolchains::detect` looks first and where `wardos-install dev rust` (`rustup-init -y
--no-modify-path`) puts one. Until that has run, `ward doctor`'s `verifier toolchain`
row warns `toolchain: none (rustup: /usr/bin/rustup-init)` with that command as the
fix, and `ward verify` runs only commands from the base system (the 0.1 stand-in for a
verifier image; Phase 4, "still ahead", replaces the bind with an image). The build
refuses an image that has `rust`, `cargo` or `gcc` in it.

Then, in this order: the binaries go to `/usr/bin`; `install-desktop.sh` places the
desktop tree ([below](#the-desktop-in-the-image)); the agents are installed from
`agents/package-lock.json` ([below](#agents-and-tamperward-in-the-image)); the
configuration files under `/usr/lib` and `/etc/firewalld`, the Flathub script and the
Plymouth theme are copied; the first-boot units, the firewall and the update timer are
enabled, the firewall's default zone set, the splash theme selected and the initramfs
rebuilt; and `bootc container lint` checks the result. Labels: `org.wardos.version`
(from `--build-arg WARDOS_VERSION`, which `build.sh` sets to `git describe --tags
--always`) and `containers.bootc=1`.

Not in the image, deliberately: the TamperWard *service* and the system-service `wardd`
of ADR-0009 (today `wardd` is per-session, spawned by `ward up`; the `tamperward` CLI
does ship); `mise` (not in Fedora; `wardos-install dev` says so); the Flathub
applications, which come at first boot, not at build time, so the image stays what
`dnf`, npm's lockfile and this repository produced.

### Packages

`packages.txt` is the one list. Rules: one name per line, a `# why` after it, blank lines
and comment lines ignored, exact Fedora package names (not "provides": `fd-find`,
`pipewire-pulseaudio`, not `fd` or `pipewire-pulse`). The Containerfile installs
`sed -e 's/#.*//' packages.txt | xargs dnf -y install`; `desktop/install.sh` reads the
same file for `dnf` or `rpm-ostree`.

CI is the source of truth for the names: `check-packages.sh` enables the COPRs and runs
`dnf repoquery` inside `quay.io/fedora/fedora:<release>` (the release read from the
Containerfile's `FROM` tag, so the check and the build cannot drift; docker on the
runner, podman locally when docker is absent) and fails listing every name that did not
resolve; a wrong name is a one-line fix there, and a name the check has not confirmed
yet carries `# unverified` until it has (none today: every name passed on Fedora 44 with
the three COPRs). `check-packages.sh --dry-run` prints the command without a container
runtime; `check-packages.sh --discover NAME...` asks the COPR API which projects carry
a name for the pinned release, which is how the COPRs below were chosen.

### COPRs

[`coprs.txt`](coprs.txt) lists COPR repositories, one `owner/project` per line with the
reason, and three things enable exactly that list the same way: the Containerfile
(`dnf5-plugins`, then `dnf copr enable` for each, before the install), `check-packages.sh`
(the same two commands in the check container, so the check sees what the build sees),
and `desktop/install.sh` (`dnf copr enable` on Workstation; on rpm-ostree, which has no
`copr` verb, the `.repo` file COPR serves is fetched into `/etc/yum.repos.d`).

A COPR is part of the image's trust set: its packages are built by the COPR's owner on
Fedora's build system, not by Fedora, and its repository file stays in the image so
`wardos-install package` layers from the same sources the image was built from. The
list is therefore short, every entry justified, and an entry is removed the day Fedora
packages the thing; it must build for the pinned release (the `fedora-<NN>-x86_64`
chroot), which the "image packages" job proves before the build runs.

Fedora retired Hyprland itself after 42 (on 44 without COPRs the check reports
`hyprland`, `hypridle`, `hyprlock`, `hyprpaper`, `hyprpicker`, `hyprpolkitagent`,
`hyprsunset`, `xdg-desktop-portal-hyprland`, `uwsm`, `satty`, `swayosd` and `lazygit`
missing), and `solopasha/hyprland`, the COPR everyone used, builds rawhide only now.
`check-packages.sh --discover NAME...` asks the COPR API which projects mention a name
and which of them build for the pinned release; the September 2026 run chose the
smallest trust set: `mineiro/hyprland` (the one repository that carries the whole
ecosystem, the successor of solopasha's), `erikreider/swayosd` (swayosd by its author)
and `atim/lazygit`. `pulsemixer` is not packaged anywhere useful; the image ships
`pavucontrol` and `wardos-setup audio` prefers pulsemixer when present.

### The desktop in the image

`install-desktop.sh SRC DESTDIR` places the [`desktop/`](../desktop) tree
([`docs/desktop.md` §Layout](../docs/desktop.md#layout)). The same script runs in the
image build (`SRC=/tmp/desktop`, `DESTDIR=/`) and from `desktop/install.sh` on an
existing Fedora, so the two installs cannot drift apart. Every part is optional: what
the tree does not contain yet is skipped.

| `desktop/…` | Installed at | Notes |
| --- | --- | --- |
| `bin/wardos-*` | `/usr/bin/` | mode 0755 |
| `lib/wardos.sh` | `/usr/lib/wardos/` | |
| `hyprland/*.conf` | `/usr/share/wardos/hypr/`, `/etc/xdg/hypr` → that directory | The directory is linked, not the file: `hyprland.conf` sources `./keybindings.conf` relative to the path it was read from |
| `config/<component>/` | `/usr/share/wardos/config/<component>/` | Copied to `~/.config` by `wardos-first-run`; re-applied by `wardos-refresh` |
| `config/{waybar,foot,mako,fuzzel,btop,fastfetch}/` | also `/etc/xdg/<component>` → the above | These read `XDG_CONFIG_DIRS`, so they work before any first-run copy; an existing real `/etc/xdg/<component>` (a Fedora that ships one) is filled, not replaced |
| `config/gtk/settings.ini` | also `/etc/xdg/gtk-3.0/settings.ini`, `/etc/xdg/gtk-4.0/settings.ini` | One file, two real directories (GTK reads `settings.ini` from `XDG_CONFIG_DIRS`; `gtk.css` only from the home directory, first-run's job) |
| `config/bash/profile.d-wardos.sh` | `/etc/profile.d/wardos.sh` | Session environment; starts `uwsm` on tty1 |
| `config/xcompose/XCompose` | `/usr/share/wardos/config/xcompose/` | Copied to `~/.XCompose` by first-run |
| `themes/` | `/usr/share/wardos/themes/` | TOML token files and backgrounds |
| `webapps/`, `tuis/`, `flatpaks.txt` | `/usr/share/wardos/` | Defaults for `wardos-webapp`, `wardos-tui`, `wardos-flathub` |
| `systemd/user/*` | `/usr/lib/systemd/user/` + `/usr/lib/systemd/user-preset/90-wardos.preset` | The preset enables every unit that has an `[Install]` section (a timer's service has none and is pulled in by its timer) |
| `systemd/system/getty@tty1.service.d/autologin.conf` | `/etc/systemd/system/getty@tty1.service.d/` | Autologin; `--no-autologin` skips it (what `desktop/install.sh` does unless told `--autologin`) |
| `shell/`, `theme/`, `tests/`, `install.sh` | — | Sources and tests never land on the host; the two crates are built in stage 1 |

`desktop/tests/install.test.sh` runs the script against a temp `DESTDIR` with a fake
tree of every kind of file and asserts on every row above.

### Autologin

The image logs `wardos` in on tty1 without a password (the getty drop-in) and
`/etc/profile.d/wardos.sh` starts Hyprland through `uwsm` there, so a machine boots
into the desktop; hyprlock, not the login prompt, is the lock. The user is not in the
image (bootc images carry no accounts): create it when making the disk,
`disk.sh --user wardos …` ([below](#users-and-luks)), or with your own config. A
different first user works too; then edit the drop-in's `--autologin` name in your
`/etc`, which bootc keeps across upgrades.

### Flathub and the default applications

Applications that are not in Fedora come from Flathub (ADR-0016: no `curl | sh`, no
AUR). `wardos-flathub.service` runs `/usr/libexec/wardos-flathub /usr/share/wardos/flatpaks.txt`
once after the first boot that has a network (`After=network-online.target`): it adds
the `flathub` remote and installs the ids in the list (`#` comments and blank lines
allowed). It never blocks login; `wardos-install app` works as soon as the remote
exists. Success writes `/var/lib/wardos/flathub.done`; a failed download leaves no
marker, shows in `systemctl --failed`, and retries on the next boot. Delete the marker
to re-run; `wardos-flathub /path/to/list` installs another list by hand.

### Plymouth

`plymouth/wardos/` is a Plymouth *script* theme: the Ward Dark ground (`#0E0F11`) fills
the screen, `WARD` sits in the middle in the text colour, a 2 px line in the muted
colour grows under it with boot progress, and the LUKS passphrase prompt is one line
of text plus one bullet per character on the same surface. No logo, no animation
([`design-language.md`](../docs/design-language.md) §2, §3). The build selects it with
`plymouth-set-default-theme wardos` when the script engine (`plymouth-plugin-script`)
is installed and falls back to `spinner` otherwise, then rebuilds the initramfs
(`dracut --no-hostonly --add ostree`, the way other bootc desktops do) because Plymouth
draws from the initramfs, not from the root filesystem. The "image build" job proves
the packages resolve, the theme is selected (`plymouth-set-default-theme` prints
`wardos` in the build log) and the dracut step runs; how the splash looks at boot is
E-09's to record.

### Base image tag

`fedora-bootc:44` pins the **current Fedora release**, not a digest. Two consequences:

1. Rebuilding on a later day gives a newer Fedora 44 content set; the image *digest* is
   what identifies a build and what evidence records (ADR-0001). CI will move to pinned
   digests (`@sha256:…`) with a renovate-style bump once E-09 has a baseline to compare.
2. A Fedora rebase (45, …) is an edit to `FROM` and a re-run of E-09, never an implicit
   change; the first one, 42 → 44 in September 2026, is recorded in ADR-0001's addendum
   (42 had reached end of life and the COPRs had dropped its chroot). `bootc` on
   installed hosts follows whatever tag their `bootc status` names.

### Agents and TamperWard in the image

ADR-0017: a WardOS install is useful the minute it boots, so the image carries the
agents `ward` exists to run and TamperWard, at pinned versions, installed at build time.

| What | Package | Command | Where |
| --- | --- | --- | --- |
| Claude Code | `@anthropic-ai/claude-code` | `/usr/bin/claude` | `/usr/lib/wardos/agents/node_modules/@anthropic-ai/claude-code/` (the native binary of the build's platform, placed by the package's postinstall) |
| Codex | `@openai/codex` | `/usr/bin/codex` | `/usr/lib/wardos/agents/node_modules/@openai/codex/` (+ the platform package) |
| TamperWard | `tamperward` 2.10.3 | `/usr/bin/tamperward` | `/usr/lib/wardos/agents/node_modules/tamperward/` |
| Node.js | Fedora `nodejs24`, `nodejs24-npm` | `/usr/bin/node` | the distro runtime (Fedora ships versioned streams, no plain `nodejs`); the build fails when it is older than the `engines` floor (22) |

[`agents/package.json`](agents/package.json) pins the three exactly and
`agents/package-lock.json` records every tarball they resolve to with its integrity
hash ([`agents/README.md`](agents/README.md): what is pinned, why, how to bump). The
Containerfile copies the two files to `/usr/lib/wardos/agents`, runs
`npm ci --omit=dev --ignore-scripts` there (`NODE_ENV=production`; every tarball is
checked against the lockfile or the build fails; nothing is fetched at first boot, no
`curl | sh`), then `npm rebuild @anthropic-ai/claude-code` for the one postinstall the
build needs (it hard-links the native binary of this platform over `bin/claude.exe`;
the lockfile carries every platform's package, which is what an aarch64 build needs,
and the musl variant is removed), links the three commands into `/usr/bin`, runs each
once (`--version`, TamperWard's `--help`) with a throwaway `HOME`, and removes npm's
cache. One `COPY`, one `RUN`; about 550 MB (Codex's platform package is 320 MB of it,
Claude Code's 210 MB, TypeScript, a TamperWard runtime dependency, 23 MB).

`/usr/lib/wardos/agents`, not `/opt`: on bootc, `/usr` is the image, replaced whole by
every update and read-only at run time, which is exactly what a pinned version wants
(a bump is a pull request and the next image carries it). `/opt` is either a symlink
into `/var` (machine state, copied at install and never updated) or a read-only
toplevel, depending on the base, and `bootc container lint` flags content under
`/var`; the ADR's `/opt/wardos/agents` is therefore realised under `/usr/lib/wardos`,
beside the desktop library. The security consequence the ADR names holds: the agents
are root-owned image content, read-only in the sandbox, unalterable by the user and
by an agent.

How `ward claude` finds them: the session sandbox binds `/usr` (and `/opt`, `/bin`,
`/lib`, `/lib64`) read-only (`crates/ward-daemon/src/sandbox.rs`, `SYSTEM_RO`) and
builds its `PATH` from the host's entries under those roots plus `/usr/bin`, so
`/usr/bin/claude` resolves inside the sandbox through
`/usr/lib/wardos/agents/node_modules/.bin/claude` the same way it does on the host;
nothing under `/home` is needed ([`docs/agent-integration.md`
§9](../docs/agent-integration.md)). `ward init` runs `tamperward init` when the binary
exists, and inside a session `tamperward run -- claude` is possible
([`docs/tamperward-integration.md` §8](../docs/tamperward-integration.md)).

Versions: `ward doctor` prints them (rows `agents`, `node`, `keys`), and the image
build's "What the image holds" step prints `claude --version`, `codex --version`,
TamperWard's `package.json` version and `node --version`, so the host, the build log
and `agents/package.json` can be compared. To bump: edit `package.json`, regenerate
the lockfile (`npm install --package-lock-only --ignore-scripts`), open a pull
request; the image build is the proof.

### Security posture

Three defaults of ADR-0017, each a file in this directory:

* **Full-disk encryption by default.** `disk.sh --type iso` generates the LUKS
  kickstart unless told `--no-luks` ([below](#users-and-luks)); the qcow2 (a
  development disk for QEMU) is unchanged, because bootc-image-builder cannot encrypt
  it and `disk.sh` refuses `--luks` for it. The `disk` workflow passes `--luks` when
  its `luks` input is `true` and `--no-luks` otherwise, so its input keeps meaning
  what it says.
* **A firewall that admits nothing inbound.** `firewalld` is in `packages.txt`,
  enabled by `90-wardos.preset` (and `systemctl enable` in the build), and its default
  zone is `wardos` (`rootfs/etc/firewalld/zones/wardos.xml`: `target="DROP"`, no
  services; the build sets `DefaultZone=wardos` in `/etc/firewalld/firewalld.conf` and
  checks the line). Outbound is unrestricted at this layer; the sandboxes carry their
  own egress policy. A command that must be reached from the LAN opens its port in the
  running configuration for as long as it runs (`firewall-cmd --add-port=PORT/tcp`,
  never `--permanent`; `wardos-share` is the shipped example, `docs/desktop.md`
  §Commands), and discovery protocols that expect unsolicited replies (mDNS for
  printers) need `firewall-cmd --add-service=mdns` the same way. `ward doctor`'s
  `firewall` row reports the service and the zone.
* **Timed image updates, rollback kept.** `bootc-fetch-apply-updates.timer` (from the
  `bootc` package: 1 h after boot, then every 8 h with a 2 h jitter) is enabled, so an
  installed host follows the reference it was installed from or switched to
  (`ghcr.io/hexrift/wardos:latest`, [below](#the-published-image-skip-the-build)).
  bootc's service runs `bootc upgrade --apply --quiet`, which reboots into a fetched
  update at once; the drop-in `bootc-fetch-apply-updates.service.d/wardos.conf` makes
  it `bootc upgrade --quiet` instead: fetch and *stage*, never reboot, because a
  desktop is not rebooted under a running agent session. The next boot runs the new
  image; `bootc status` shows it as staged meanwhile. `wardos-update` (`bootc upgrade`)
  is the manual path, `bootc rollback` boots the previous deployment, which every
  upgrade keeps ([`boot/README.md`](boot/README.md) §4, §6). The build log's "What the
  image holds" step prints `systemctl is-enabled` for the timer and the firewall.

## Size

A first pull of `ghcr.io/hexrift/wardos:latest` is the whole host, and it took over ten
minutes: on 2026-09-08, before the work below, the registry's manifest for
`latest-x86_64` summed to **2,849,473,784 bytes compressed** (2.65 GiB, 74 layers: the
`dnf` layer 1.23 GB, the last layer with the rebuilt initramfs 277 MB, the agents
233 MB, the binaries 145 MB), the `disk` workflow's qcow2 was 2.94 GiB
(`wardos-v0.2.0-x86_64.qcow2` of run 4; 2.91 GiB as `.zst`, because
bootc-image-builder compresses the filesystem inside) and the ISO 3.44 GiB (3.37 GiB
`.zst`). Every pull, every `bootc upgrade` and every disk pays for what the manifest
names, so the manifest is kept to what the desktop renders and what a session needs;
the rest is a Flatpak, a rustup toolchain in the user's home, or absent.

**Baseline: `install_weak_deps=False` (#66, #70).** Run 2 of the `disk` workflow
(34216758319, the last build before #66) uploaded a qcow2-only artifact of
3,377,829,214 bytes (3.15 GiB; the artifact zip of a qcow2 that is compressed inside
is the qcow2's size within a percent). Run 4 (34224721518, the first after it, with
nothing else in the manifest changed in between) has the same qcow2 at 2.94 GiB: about
210 MiB less for the "recommended" extras alone. Nothing the desktop needs was a weak
dependency that anyone has found; the names to look at first when E-09 finds a gap are
the recommendations of the installed set, listed offline with `podman run --rm
quay.io/fedora/fedora:44 dnf -q repoquery --recommends $(sed -e 's/#.*//' packages.txt)`
after enabling the COPRs the way `check-packages.sh` does. Known candidates:
`gnome-keyring-pam` (the keyring is unlocked at login without it only because the
image has no password prompt), `fwupd-plugin-uefi-capsule-data` (dbx updates),
`pipewire-gstreamer` (media in GTK applications), `mesa-va-drivers` (video decoding in
Chromium); each is one line in `packages.txt` if a boot test wants it, never a return
to weak dependencies.

**What went, and the expected saving** (installed sizes from the Fedora 44 packages;
the measured number is the line `docker image inspect --format '{{.Size}}'` prints
after every "image build" job in `image.yml`, and the pull size is the manifest sum
above, recomputed with the same command against the next `latest-x86_64`):

| Removed | Why | Expected saving |
| --- | --- | --- |
| `firefox` (#67) | One browser. Chromium is the default browser, the web-app engine (`wardos-webapp`, `--app`, one profile per app and per project) and what the theme's `chromium.json` colours; nothing in `desktop/` names Firefox except the window rule that puts the Flatpak on the web workspace. Firefox is `wardos-install app org.mozilla.firefox`, one command, Flathub's build, sandboxed. | ~290 MB |
| `rust`, `cargo` (#68) | ADR-0001: no toolchain on the host. They were the "one temporary exception" for the verifier; the verifier reads `~/.rustup` and `~/.cargo` instead, filled by `wardos-install dev rust`. With them go what only they pulled in: `rust-std-static`, `gcc`, `binutils`, `glibc-devel`, `kernel-headers` (`llvm-libs` stays: Mesa needs it). Neither `gcc` nor `make` is in the manifest because nothing in it needs a compiler at run time: `python3` is used for plain scripts, the agents' native pieces are prebuilt binaries from the lockfile (`npm ci --ignore-scripts`), bootc kernels ship their modules and there is no DKMS. The build refuses the image if `rust`, `cargo` or `gcc` is in it. Added: `rustup` (the installer, ~10 MB). | ~500 MB |
| `cascadia-code-nf-fonts` (#69) | No component names it: the bar is words in Inter and JetBrains Mono (`config/waybar/style.css`), the menus and terminals take the theme's `mono` list, and no shipped file uses a Nerd Font glyph. | ~30 MB |
| `google-noto-sans-fonts`, `google-noto-emoji-fonts` (#69) | Inter is the sans everywhere (every theme's first `sans`, hyprlock, the bar); the fallback for Latin, Greek and Cyrillic is DejaVu (fontconfig's own default, now named in the manifest so it cannot vanish); one emoji font, the colour one (`wardos-menu-select` emoji, notifications, the browser). Added: `dejavu-sans-fonts`, `dejavu-sans-mono-fonts` (~3 MB, usually already present) and `google-noto-sans-cjk-vf-fonts` as the one CJK fallback (a variable font, one file for the five scripts, ~35 MB; the static family it replaces in the usual desktop set is over 100 MB), so a page or a file name in Japanese or Chinese renders instead of boxes. | ~15 MB net |
| Locales other than `en_US` and `C.UTF-8` (#69) | `glibc-langpack-en` is in the manifest and `glibc-all-langpacks` (the 220 MB locale archive) is removed when the base image carries it; the rpm macro `%_install_langs en_US:en` (`/etc/rpm/macros.image-language-conf`, written before the install, kept in the image so later layering matches) drops every other language's translations and Chromium's other locale packs as the packages unpack. The kickstart and the desktop are `en_US.UTF-8`; the build asserts `locale -a` lists it, so a filter that took too much fails the build rather than a boot. Not done: `tsflags=nodocs`, which would also drop the manual pages, and the desktop keeps those. | ~220 MB if the base carried the archive, ~100 MB of translations |

Together, roughly a gigabyte installed, about a third of the pull; the table is the
expectation and the CI line is the fact. What stays big and why: the agents
(`agents/`, 550 MB, ADR-0017: useful the minute it boots), Chromium (~300 MB, the
browser and the web-app engine), the kernel with its modules and the initramfs, Mesa
and LLVM (the compositor), Node (the agents' runtime).

## Where the binaries come from

The host stage copies the binaries from one of two stages, chosen with
`--build-arg WARDOS_SOURCE` (`image/build.sh --source`):

| Source | What happens | Use |
| --- | --- | --- |
| `release` (default) | downloads `wardos-<ver>-<arch>-linux.tar.gz` for `WARDOS_RELEASE` from the GitHub release (`<arch>` from the platform being built: `TARGETARCH` amd64 → `x86_64`, arm64 → `aarch64`) and refuses to continue unless its SHA-256 matches `WARDOS_SHA256` (x86_64) or `WARDOS_SHA256_AARCH64` (`build.sh` fetches the published checksum for `--arch`) | every image that leaves your machine: reproducible from a known, tested release |
| `builder` (`--source checkout`) | compiles this working tree with `docker.io/library/rust:1.94.1` (the channel of `rust-toolchain.toml`; bump both together), `--locked` | development images of unreleased changes; the "image build" CI job |

Five binaries: `ward`, `wardd`, `ward-agent` (required; the build fails without them),
`ward-shell` and `wardos-theme-render` (the shell's surfaces and the theme renderer).
The builder stage compiles all five (`desktop/shell`, `desktop/theme` are workspace
crates); the release stage copies the last two when the tarball has them, which
release tarballs from **v0.2** do (`release.yml` packages five from now on)
and earlier releases do not: an image built from one has the desktop's packages and
configuration but no shell surfaces, and `ls -l /usr/bin/ward*` in the build log says
which arrived. The Rust image is Debian-based; its glibc is older than Fedora 44's, so
the binaries run on the host without a rebuild.

The tools and the image therefore have separate cadences: `vX.Y.Z` tags release the
tools; images carry the release they embed in `org.wardos.version` plus the build's
`git describe`, and are tagged by date when published (`wardos:2026.09`).

## Building on a Fedora host

Requirements: a Fedora (or any bootc-capable) host with `podman` ≥ 4.9, `git`, and root,
because `bootc-image-builder` reads root's container storage. Roughly 12 GB of free
disk for the build layers (the desktop's packages are most of it) and the output image.

```sh
git clone https://github.com/hexrift/WardOS && cd WardOS
sudo ./image/build.sh                                        # -> localhost/wardos:<git describe>
sudo ./image/disk.sh --type qcow2 --user wardos --password …  # -> image/out/qcow2/disk.qcow2
sudo ./image/disk.sh --type iso --user wardos                # -> image/out/bootiso/install.iso, LUKS
```

Both scripts print the exact command they are about to run; `--dry-run` prints it and
exits without needing podman:

```sh
./image/build.sh --dry-run
./image/disk.sh --type qcow2 --user wardos --password x --dry-run
```

`--rootfs` defaults to `btrfs` (ADR-0001; `/work` snapshots want it). The builder image is
`quay.io/centos-bootc/bootc-image-builder:latest`, overridable with
`BOOTC_IMAGE_BUILDER=`; pin it to a digest once E-09 records which version produced the
baseline.

### Users and LUKS

`disk.sh --user NAME` writes a bootc-image-builder config (`<output>/config.toml`, mode
0600, printed with the password redacted) that creates the first user in `wheel`, with
`--password PW` (or `WARDOS_PASSWORD` in the environment, which keeps it out of `ps`)
and/or `--ssh-key FILE`; one of the two is required, or nobody could use `sudo`. The
desktop's autologin expects `wardos`. `--config FILE` passes your own TOML instead
(the two are exclusive); a minimal one:

```toml
[[customizations.user]]
name = "wardos"
password = "change-me-on-first-login"
groups = ["wheel"]
```

`disk.sh --type iso` gives full-disk encryption **by default** (ADR-0017); `--no-luks`
is the opt-out, `--luks` the explicit form, and the dry-run says which applies. The
blueprint that bootc-image-builder consumes knows `plain`, `lvm` and `btrfs` partitions
and nothing encrypted (`osbuild/blueprint`, `disk_customizations.go`), so a qcow2
cannot be encrypted by the builder and `disk.sh` refuses `--luks` for it; the
installer ISO can, through an Anaconda kickstart that `disk.sh` generates (a `--config`
of your own carries its own partitioning, so no kickstart is generated next to it):

```text
zerombr
clearpart --all --initlabel --disklabel=gpt
autopart --noswap --type=btrfs --encrypted
network --bootproto=dhcp --device=link --activate --onboot=on
lang en_US.UTF-8 / keyboard us / timezone UTC --utc / rootpw --lock
user --name=wardos --groups=wheel --password=… --plaintext
reboot
```

`autopart --encrypted` without `--passphrase` makes Anaconda ask for one during the
installation, so no passphrase is ever written to a file (*unverified* until E-09; the
generated file says so). bootc-image-builder refuses `[[customizations.user]]` next to a
custom kickstart, which is why the user becomes a kickstart `user` line in this mode
(`--no-luks --user` falls back to `[[customizations.user]]`). At boot the passphrase
is typed on the Plymouth surface.

### Boot-testing in QEMU

```sh
qemu-system-x86_64 -enable-kvm -m 4096 -cpu host \
  -drive file=image/out/qcow2/disk.qcow2,if=virtio,format=qcow2 \
  -bios /usr/share/edk2/ovmf/OVMF_CODE.fd \
  -device virtio-vga-gl -display gtk,gl=on
```

The last line is the display: Hyprland needs a GPU and a window to draw in, so a
`-nographic` boot stops at the text login on the serial console and never reaches the
desktop. Without GTK in your QEMU build, `-device virtio-vga -display sdl` works too.
`disk.sh` hands `image/out/` back to the user who ran `sudo`, so QEMU can open the disk
without root. UEFI firmware comes from the `edk2-ovmf` package; Secure Boot is off in
this configuration, see [`secure-boot/`](secure-boot/README.md) for the variant with it
on.

### The published image: skip the build

Every merge to `main` that passes the image build pushes the result to
`ghcr.io/hexrift/wardos` (`:latest` and `:<short sha>`, for x86_64 and aarch64 both;
`:latest-<arch>` names one architecture, [below](#aarch64-and-apple-silicon)). A
machine that only wants a disk never builds anything:

```sh
sudo WARDOS_PASSWORD='choose-one' image/disk.sh --type qcow2 --user wardos \
  --image ghcr.io/hexrift/wardos:latest
```

`disk.sh` pulls a registry reference it does not have and hands it to
bootc-image-builder; five to ten minutes later the qcow2 is there. An installed WardOS
follows the same reference: `bootc switch ghcr.io/hexrift/wardos:latest` once, then
`wardos-update` (`bootc upgrade`) tracks every merge. Building locally is for changing
the image, not for using it.

Build time, when you do build: the Containerfile keeps its steps few because every step
commits a multi-gigabyte layer (about fifteen seconds each even for a one-file copy);
`dnf` installs with `install_weak_deps=False`, so the image holds only what
`packages.txt` names; and `build.sh` passes `--format docker` so the Containerfile's
`pipefail` shell is honoured under podman too. Compiling the tools is the slow part of a
checkout build (five to ten minutes); `--source release` downloads them instead. Both
`dnf` and `cargo` run behind cache mounts (`RUN --mount=type=cache`, honoured by docker
and by podman/buildah): the second build on a machine reuses the downloaded RPMs and the
compiled dependencies, so a rebuild after a small change takes a minute or two instead
of ten. Nothing from a cache lands in the image. Decision: caches over a smaller
manifest, because the manifest is the product and the cache is free.

### Disk images from CI

Nobody needs a Fedora box to get a WardOS disk. The `disk` workflow
([`.github/workflows/disk.yml`](../.github/workflows/disk.yml)) runs `build.sh` and
`disk.sh` on a GitHub runner, where bootc-image-builder has the privileged podman it
needs, and publishes the result:

* **By hand**: Actions → *disk* → *Run workflow*. Choose `qcow2`, `iso` or `both`, the
  architecture (`x86_64`, `aarch64`, or `both` for one job per architecture, each on a
  runner of that architecture), the binaries (`checkout` compiles this commit,
  `release` takes the published tarball of `--release`), the first user (`wardos`,
  which the autologin expects) and, for the ISO, `luks`. The disks appear as the run's
  `wardos-disks-<arch>` artifact for 14 days, with a `SHA256SUMS.<arch>`.
* **On every published release**: both disks of both architectures are built from that
  release's tarballs and attached to the release as `wardos-<tag>-<arch>.qcow2.zst` and
  `.iso.zst`. GitHub caps a release asset at 2 GiB and bootc-image-builder's disks are
  already compressed inside (zstd gains about 1 %), so a disk over the cap is attached
  in 1900 MiB parts: `cat wardos-<tag>-<arch>.iso.zst.part* > wardos-<tag>-<arch>.iso.zst`,
  check it against `SHA256SUMS.<arch>`, then `zstd -d`. Decision: parts rather than an
  external host, so a release stays one page with everything on it; the run's artifact
  carries the same files unsplit for 14 days.

The first user's password in these disks is `wardos`. Change it at first login
(`passwd`); the ISO with `luks` additionally asks for the disk passphrase during the
install. The same workflow runs `check-packages.sh --arch aarch64 --discover` so the
log says whether the COPRs the image depends on still build for aarch64.

**On a Mac.** Docker Desktop can build the container image
(`docker build -f image/Containerfile --platform linux/arm64 -t wardos .` on Apple
silicon, `linux/amd64` on Intel) and run it for a look around, but cannot make the
disk: bootc-image-builder needs loop devices and a privileged Linux podman, which
Docker Desktop's VM does not provide. Download the qcow2 of the Mac's own architecture
from CI instead and boot it natively in [UTM](https://mac.getutm.app)
([below](#aarch64-and-apple-silicon)), or write the ISO to a USB stick for a PC.

### aarch64 and Apple silicon

Everything the x86_64 host gets exists for aarch64 too, built natively on GitHub's
`ubuntu-24.04-arm` runners (free for public repositories), never cross-compiled or
emulated:

| What | Built by | Name |
| --- | --- | --- |
| The five binaries, from release **v0.3** | `release.yml`, one matrix job per architecture, the tarballs attached to one release | `wardos-<ver>-aarch64-linux.tar.gz` + `.sha256`; `install.sh` picks the tarball by `uname -m` |
| The image, on every merge to `main` | `image.yml`, job `image build (aarch64)`: the same `docker build --platform linux/arm64 --build-arg WARDOS_SOURCE=builder`, the same look inside, `bootc container lint` | `ghcr.io/hexrift/wardos:latest-aarch64`, `:<sha>-aarch64`; the x86_64 image is also `:latest-x86_64`, `:<sha>-x86_64`; `:latest` and `:<sha>` are manifest lists pointing at both once both builds passed (`podman pull` and `bootc switch` resolve the machine's own), and stay the x86_64 image when the aarch64 build failed |
| The disks | `disk.yml` with `arch=aarch64` (or `both`), on an arm64 runner: `build.sh --arch aarch64` and `disk.sh --arch aarch64`, bootc-image-builder running natively | `wardos-<ver>-aarch64.qcow2`, `.iso`; artifact `wardos-disks-aarch64`; on a release `.zst` beside the x86_64 ones |

What makes it possible: `quay.io/fedora/fedora-bootc:44` is multi-arch, the three COPRs
of `coprs.txt` have `fedora-44-aarch64` chroots (the `aarch64 chroots` job checks on
every dispatch), every name in `packages.txt` is noarch or built for aarch64 (the
`image build (aarch64)` job is the proof, on every merge), and bootc-image-builder is
published for arm64. Nothing in the desktop tree is architecture-specific. The
Containerfile's release stage reads `TARGETARCH` (which docker and podman set from
`--platform`) to fetch the tarball of the platform being built and checks it against
`WARDOS_SHA256_AARCH64`; the builder stage compiles for that platform by itself.

Locally, `build.sh --arch aarch64` passes `--platform linux/arm64` and the aarch64
checksum. On an arm64 host (an Asahi or Fedora-on-Mac box, a Graviton VM) that is a
native build; on an x86_64 host podman runs the Rust build and `dnf` under
`qemu-user-static`, which works and takes hours, so prefer the published image or CI.
`disk.sh --arch aarch64` passes `--target-arch arm64` to bootc-image-builder: a no-op on
an arm64 host, and the builder's *experimental* cross path (needs `qemu-user`, qcow2
only: it refuses an ISO for another architecture, and so does `disk.sh`) elsewhere. CI
never crosses: the arm64 runner builds the aarch64 image and disk. Before v0.3 there is
no aarch64 tarball, so `build.sh --arch aarch64 --source release` says so and stops;
`--source checkout` works for any commit.

**Getting the aarch64 disk.** Actions → *disk* → *Run workflow* with `arch=aarch64`,
`type=qcow2` (the artifact `wardos-disks-aarch64`), or take
`wardos-<ver>-aarch64.qcow2.zst` from a release and `zstd -d` it. The first user is
`wardos`, password `wardos`; change it at first login.

**UTM on an Apple-silicon Mac** (M1 and later; UTM 4.x from [mac.getutm.app](https://mac.getutm.app)
or the App Store):

1. *Create a New Virtual Machine* → *Virtualize* → *Linux*. Tick **Use Apple
   Virtualization** (the macOS hypervisor: native speed, virtio devices, a virtio-gpu
   display); leave *Boot from kernel image* off and skip the ISO: the qcow2 already has
   a bootable system.
2. Hardware: **4096 MB** of memory and **4 CPU cores** (the desktop is comfortable with
   that; more helps compiles). Storage: any size, it is replaced next.
3. Save, then open the machine's settings: remove the empty drive UTM created and
   **Import** the qcow2 as a **virtio** drive. Apple's framework wants raw disks; UTM
   converts on import, or do it yourself first with `qemu-img convert -O raw
   wardos-<ver>-aarch64.qcow2 wardos.img` (`brew install qemu`). Disk size grows with
   use; the qcow2 ships small.
4. Boot is **UEFI** (the only firmware Apple Virtualization offers for Linux, and what
   the image expects: bootc installs to the EFI system partition). Start the machine:
   Plymouth, the tty1 autologin, Hyprland.

Caveats, all *unverified* on real Apple hardware until someone records them the way
E-09 does for the reference laptop:

* **No Secure Boot.** Apple Virtualization boots Linux without a Secure Boot chain, so
  the plan in [`secure-boot/`](secure-boot/README.md) does not apply inside the VM;
  `bootc status` still verifies the image digest.
* **Screen scaling.** The virtio-gpu display appears to Hyprland at the Retina pixel
  size; text is tiny at scale 1. Set the scale (`wardos-setup monitors`, or
  `monitor=,preferred,auto,2` in `~/.config/hypr/monitors.conf`) or lower UTM's display
  resolution; UTM's own *Retina* option doubles the pixels the guest sees.
* **Devices.** No fingerprint reader, FIDO2 key or Bluetooth reaches the guest
  (`fprintd`, `pam-u2f`, `bluez` idle); USB passthrough needs the QEMU backend. The
  clipboard is not shared (the SPICE agent belongs to QEMU). Nested virtualization for
  `podman` inside the VM exists from the M3 with macOS 15; earlier chips run containers
  without it, which is what podman does anyway.
* **The x86_64 disk on Apple silicon** boots under UTM's QEMU backend as an emulated
  machine (choose *Emulate*, x86_64, UEFI) and is slow; it is the wrong disk for that
  Mac. An Intel Mac takes the x86_64 qcow2 the same way as above, natively.

Windows: the tools install in WSL2 ([`docs/install.md`](../docs/install.md) §7); the
image and its disks are for a VM or a PC, not for WSL2.

## First boot: what to expect

1. `systemd-tmpfiles` creates `/var/lib/wardos` (mode 0755, root).
2. `wardos-firstboot.service` runs `/usr/bin/ward doctor` once and writes its report to
   `/var/lib/wardos/doctor.txt`; the unit is skipped on later boots while that file exists
   (delete it to re-run, or `systemctl start wardos-firstboot`).
3. `wardos-flathub.service` waits for the network, adds Flathub and installs the default
   applications in the background ([above](#flathub-and-the-default-applications)).
4. tty1 logs `wardos` in and `uwsm` starts Hyprland; `wardos-first-run` copies the
   configs, asks for a theme, runs `ward doctor` and shows the keys.
   `bootc container lint` ran clean at the end of the build (10 checks, no warnings
   once the install-time caches and logs under `/var`, `/run` and `/tmp` are swept).
5. `sysctl kernel.unprivileged_userns_clone` does not exist on Fedora kernels; the sysctl
   file marks it optional (`-`), so `systemd-sysctl` logs it and continues. Check with
   `sysctl user.max_user_namespaces` (non-zero) and `bwrap --unshare-all -- true`.
6. Verify the runtime: `ward selftest` should pass every group it passes on a Fedora
   development host; `ward doctor` (or `cat /var/lib/wardos/doctor.txt`) lists bubblewrap,
   cgroups v2, user namespaces, the verifier toolchain (a warning naming
   `wardos-install dev rust` until a user has run it), `podman`, and the ADR-0017 rows:
   `node`, `agents` (the three versions), `keys` (a warning until `ward vault set
   ANTHROPIC_API_KEY`), `firewall` (`firewalld active, default zone wardos`).
7. `bootc status` shows the booted image and its digest. Record both in the E-09 result.
   `systemctl list-timers bootc-fetch-apply-updates.timer` shows the next update check;
   after one, a staged deployment appears in `bootc status` and the next boot runs it.

Updates (`bootc upgrade`, which `wardos-update` wraps), switching between images, and
rollback (`bootc rollback`: the previous deployment stays until the next upgrade, the
Fedora way of Omarchy's snapper snapshots) are documented in
[`boot/README.md`](boot/README.md).

## The desktop on an existing Fedora

[`desktop/install.sh`](../desktop/install.sh) applies the same desktop to a Fedora 44
that is already installed: Workstation (`dnf`), Silverblue and Kinoite (`rpm-ostree
install`, layered, active after a reboot). See [`docs/install.md`](../docs/install.md),
"Desktop".

## Checks that run without a boot

CI runs, on every pull request and push (`verify.yml`):

| Job | What |
| --- | --- |
| `image lint` | hadolint on `Containerfile`, shellcheck (`--severity=style`) on `image/*.sh`, the dry-runs of `build.sh`, `disk.sh` (plain and `--luks --user`), `check-packages.sh`, and `install-desktop.sh --help` |
| `image packages` | `check-packages.sh`: every name in `packages.txt` exists in the pinned Fedora release (plus `coprs.txt`) |
| `hyprland config` | `image/check-hyprland.sh`: `Hyprland --verify-config` on `desktop/hyprland/` inside a `fedora:<release>` container with the COPRs, so the tree matches the compositor the image ships |
| `desktop scripts` | `desktop/tests/run.sh`, which includes `install.test.sh` (install-desktop, desktop/install.sh, wardos-flathub, check-packages.sh, disk.sh) |

and, in `image.yml` on `main` and on pull requests that touch `image/`, `desktop/`, the
crates or `Cargo.lock`: `image build` and `image build (aarch64)`, the real `docker
build` with the checkout's binaries on a runner of each architecture, the image's size
printed right after it (`docker image inspect --format '{{.Size}}'`, the number the
[Size](#size) section tracks), followed by a look inside (`/usr/bin/ward*`,
`/usr/share/wardos`, the user preset, `/etc/xdg/hypr`,
the enabled units including the firewall and the update timer, the firewall's default
zone, the three agent commands with their versions and `node --version`, the Plymouth
theme) and `bootc container lint`. It is the check that catches a package name that
exists but conflicts (or exists for x86_64 only), a `dracut` flag that does not, a
lockfile that no longer installs, or a desktop file the installer mishandles.

Locally:

```sh
bash -n image/*.sh && shellcheck --severity=style image/*.sh
hadolint image/Containerfile        # reads ../.hadolint.yaml
./image/check-packages.sh           # needs docker or podman and the network
bash desktop/tests/run.sh
docker build -f image/Containerfile --build-arg WARDOS_SOURCE=builder -t wardos:ci .
```

What no check can do and E-09 must: that the qcow2 boots, that `getty@tty1` logs the
user in and `uwsm` brings Hyprland up, that the Plymouth theme is the early one, that
Anaconda asks for the LUKS passphrase, that `ward doctor` exits 0 on the host.
