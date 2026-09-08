#!/usr/bin/env bash
# image/install-desktop.sh places a desktop tree into a DESTDIR; desktop/install.sh
# applies it to an existing Fedora with mocked dnf / rpm-ostree / sudo / systemctl /
# flatpak; image/flathub.sh adds Flathub and installs the default list.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"

repo=$WARDOS_ROOT/..
# The Fedora release the image pins; the scripts read the same line.
rel=$(sed -n 's|^FROM quay.io/fedora/fedora-bootc:\([0-9][0-9]*\)$|\1|p' "$repo/image/Containerfile")
[[ "$rel" =~ ^[0-9]+$ ]] || fail "no fedora-bootc:<release> FROM line in image/Containerfile"
assert_link() { [[ -L "$1" ]] || fail "expected symlink $1"; assert_eq "$(readlink "$1")" "$2"; }
assert_missing() { [[ ! -e "$1" ]] || fail "unexpected file $1"; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "expected '$2' in $1:
$(cat "$1")"; }

# --- a fake desktop tree with every kind of file the layout names --------------------
make_tree() {
  local t=$1
  mkdir -p "$t"/{bin,lib,hyprland,config/{waybar,foot,mako,fuzzel,btop,fastfetch,hyprlock,nvim,gtk,chromium,bash,xcompose},themes/ward-dark/backgrounds,systemd/user,systemd/system/getty@tty1.service.d,webapps,tuis,shell/src,theme/src,tests}
  printf '#!/usr/bin/env bash\necho hi\n' >"$t/bin/wardos-hello"
  chmod 0644 "$t/bin/wardos-hello" # the installer must make it executable
  echo 'wardos_lib=1' >"$t/lib/wardos.sh"
  echo 'source = ./keybindings.conf' >"$t/hyprland/hyprland.conf"
  echo 'bind = SUPER, Q, killactive' >"$t/hyprland/keybindings.conf"
  echo '{}' >"$t/config/waybar/config"
  echo 'x' >"$t/config/foot/foot.ini"
  echo 'x' >"$t/config/mako/config"
  echo 'x' >"$t/config/fuzzel/fuzzel.ini"
  echo 'x' >"$t/config/btop/btop.conf"
  echo 'x' >"$t/config/fastfetch/config.jsonc"
  echo 'x' >"$t/config/hyprlock/hyprlock.conf"
  echo 'x' >"$t/config/nvim/init.lua"
  echo '[Settings]' >"$t/config/gtk/settings.ini"
  echo '* {}' >"$t/config/gtk/gtk.css"
  echo '--ozone-platform=wayland' >"$t/config/chromium/chromium-flags.conf"
  echo 'export WARDOS=1' >"$t/config/bash/profile.d-wardos.sh"
  echo 'include "%L"' >"$t/config/xcompose/XCompose"
  echo '[meta]' >"$t/themes/ward-dark.toml"
  echo 'png' >"$t/themes/ward-dark/backgrounds/1.png"
  printf '[Unit]\nDescription=bar\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n' >"$t/systemd/user/wardos-bar.service"
  printf '[Unit]\nDescription=battery\n[Service]\nExecStart=/bin/true\n' >"$t/systemd/user/wardos-battery-monitor.service"
  printf '[Unit]\nDescription=battery timer\n[Timer]\nOnUnitActiveSec=5m\n[Install]\nWantedBy=timers.target\n' >"$t/systemd/user/wardos-battery-monitor.timer"
  printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --noclear --autologin wardos %%I linux\n' >"$t/systemd/system/getty@tty1.service.d/autologin.conf"
  echo 'name=GitHub' >"$t/webapps/github.conf"
  echo 'name=btop' >"$t/tuis/btop.conf"
  printf '# default apps\norg.signal.Signal\n\ncom.spotify.Client # music\n' >"$t/flatpaks.txt"
  echo 'fn main() {}' >"$t/shell/src/main.rs"
  echo 'fn main() {}' >"$t/theme/src/main.rs"
  echo 'x' >"$t/tests/lib.sh"
  echo 'x' >"$t/install.sh"
}

# --- install-desktop.sh: full tree -------------------------------------------------
setup_env
make_tree "$TMP/desktop"
dest=$TMP/root
bash "$repo/image/install-desktop.sh" "$TMP/desktop" "$dest" >"$TMP/out"

assert_file "$dest/usr/bin/wardos-hello"
[[ -x "$dest/usr/bin/wardos-hello" ]] || fail "bin must be executable"
assert_file "$dest/usr/lib/wardos/wardos.sh"
assert_file "$dest/usr/share/wardos/hypr/hyprland.conf"
assert_file "$dest/usr/share/wardos/hypr/keybindings.conf"
# The whole directory is linked, so `source = ./keybindings.conf` resolves through it.
assert_link "$dest/etc/xdg/hypr" /usr/share/wardos/hypr
assert_file "$dest/usr/share/wardos/config/waybar/config"
assert_file "$dest/usr/share/wardos/config/hyprlock/hyprlock.conf"
assert_file "$dest/usr/share/wardos/config/nvim/init.lua"
for c in waybar foot mako fuzzel btop fastfetch; do
  assert_link "$dest/etc/xdg/$c" "/usr/share/wardos/config/$c"
done
assert_file "$dest/etc/xdg/gtk-3.0/settings.ini"
assert_file "$dest/etc/xdg/gtk-4.0/settings.ini"
assert_missing "$dest/etc/xdg/gtk-3.0/gtk.css"
assert_file "$dest/usr/share/wardos/config/gtk/gtk.css"
# Only the XDG_CONFIG_DIRS components get a /etc/xdg entry; the rest (hypr*, nvim,
# chromium-flags.conf, XCompose) are copied to the home directory by wardos-first-run.
assert_missing "$dest/etc/xdg/hyprlock"
assert_missing "$dest/etc/xdg/nvim"
assert_missing "$dest/etc/xdg/chromium"
assert_file "$dest/usr/share/wardos/config/chromium/chromium-flags.conf"
assert_file "$dest/etc/profile.d/wardos.sh"
assert_file "$dest/usr/share/wardos/config/xcompose/XCompose"
assert_file "$dest/usr/share/wardos/themes/ward-dark.toml"
assert_file "$dest/usr/share/wardos/themes/ward-dark/backgrounds/1.png"
assert_file "$dest/usr/lib/systemd/user/wardos-bar.service"
assert_file "$dest/usr/lib/systemd/user/wardos-battery-monitor.service"
assert_file "$dest/usr/lib/systemd/user/wardos-battery-monitor.timer"
preset=$dest/usr/lib/systemd/user-preset/90-wardos.preset
assert_file "$preset"
assert_contains "$preset" "enable wardos-bar.service"
assert_contains "$preset" "enable wardos-battery-monitor.timer"
# A service without [Install] is pulled in by its timer, never preset-enabled.
! grep -q "enable wardos-battery-monitor.service" "$preset" || fail "preset lists a unit without [Install]"
assert_file "$dest/etc/systemd/system/getty@tty1.service.d/autologin.conf"
assert_file "$dest/usr/share/wardos/webapps/github.conf"
assert_file "$dest/usr/share/wardos/tuis/btop.conf"
assert_file "$dest/usr/share/wardos/flatpaks.txt"
# Sources, tests and the installer itself never land on the host.
assert_missing "$dest/usr/share/wardos/shell"
assert_missing "$dest/usr/share/wardos/theme"
assert_missing "$dest/usr/share/wardos/tests"
assert_missing "$dest/usr/share/wardos/install.sh"
assert_missing "$dest/usr/share/wardos/src"
assert_contains "$TMP/out" "bin"

# --- install-desktop.sh: --no-autologin, an existing /etc/xdg/<c> directory, a sparse tree
rm -rf "$dest"
mkdir -p "$dest/etc/xdg/foot"
echo 'old' >"$dest/etc/xdg/foot/other.ini"
bash "$repo/image/install-desktop.sh" --no-autologin "$TMP/desktop" "$dest" >/dev/null
assert_missing "$dest/etc/systemd/system/getty@tty1.service.d/autologin.conf"
# An existing real directory is kept and filled, not replaced by a link.
[[ ! -L "$dest/etc/xdg/foot" ]] || fail "existing /etc/xdg/foot must not become a link"
assert_file "$dest/etc/xdg/foot/foot.ini"
assert_file "$dest/etc/xdg/foot/other.ini"
# Idempotent: a second run over the same DESTDIR succeeds.
bash "$repo/image/install-desktop.sh" --no-autologin "$TMP/desktop" "$dest" >/dev/null

rm -rf "$dest" "$TMP/sparse"
mkdir -p "$TMP/sparse/hyprland"
echo 'x' >"$TMP/sparse/hyprland/hyprland.conf"
bash "$repo/image/install-desktop.sh" "$TMP/sparse" "$dest" >/dev/null
assert_file "$dest/usr/share/wardos/hypr/hyprland.conf"
assert_missing "$dest/usr/lib/systemd/user-preset/90-wardos.preset"

# Usage and argument errors.
bash "$repo/image/install-desktop.sh" --help | grep -q 'install-desktop.sh' || fail "--help prints usage"
! bash "$repo/image/install-desktop.sh" "$TMP/does-not-exist" "$dest" 2>/dev/null || fail "missing SRC must fail"
! bash "$repo/image/install-desktop.sh" "$TMP/sparse" 2>/dev/null || fail "missing DESTDIR must fail"

# --- desktop/install.sh on Workstation (dnf) -------------------------------------
setup_env
mock dnf
mock systemctl
mock flatpak
mock sudo 'exec "$@"'
root=$TMP/root
bash "$repo/desktop/install.sh" --destdir "$root" >"$TMP/out" 2>&1 || fail "install.sh failed:
$(cat "$TMP/out")"
# coprs.txt is empty today: no plugin install, no copr enable (the paths are exercised
# below with a list of their own).
assert_not_logged 'dnf5-plugins'
assert_not_logged 'copr enable'
assert_logged '^sudo dnf install -y .*hyprland'
assert_logged '^dnf install -y .*bubblewrap'
assert_not_logged '^rpm-ostree'
assert_not_logged '^curl'
assert_logged '^sudo flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo$'
assert_logged '^systemctl --user daemon-reload$'
# The real desktop tree of this checkout landed under --destdir.
assert_file "$root/usr/share/wardos/hypr/hyprland.conf"
assert_file "$root/usr/share/wardos/hypr/bindings.conf"
assert_link "$root/etc/xdg/hypr" /usr/share/wardos/hypr
assert_file "$root/usr/share/wardos/themes/ward-dark.toml"
assert_file "$root/usr/share/wardos/config/bash/bashrc"
assert_file "$root/etc/profile.d/wardos.sh"
assert_file "$root/etc/xdg/gtk-3.0/settings.ini"
assert_file "$root/usr/share/wardos/flatpaks.txt"
assert_link "$root/etc/xdg/waybar" /usr/share/wardos/config/waybar
assert_file "$root/usr/lib/systemd/user/wardos-approve.service"
for u in swayosd.service wardos-approve.service wardos-battery-monitor.timer; do
  assert_contains "$root/usr/lib/systemd/user-preset/90-wardos.preset" "enable $u"
  assert_logged "^systemctl --user preset .*$u"
done
# Existing Fedora: no tty1 autologin unless asked for.
assert_missing "$root/etc/systemd/system/getty@tty1.service.d/autologin.conf"
grep -q 'uwsm start hyprland.desktop' "$TMP/out" || fail "login instructions missing:
$(cat "$TMP/out")"

# --- desktop/install.sh on Silverblue (rpm-ostree) ---------------------------------
setup_env
mock rpm-ostree
mock systemctl
mock flatpak
mock curl
mock sudo 'exec "$@"'
touch "$TMP/ostree-booted"
WARDOS_OSTREE_MARKER=$TMP/ostree-booted bash "$repo/desktop/install.sh" --destdir "$TMP/root" >"$TMP/out" 2>&1 || fail "install.sh (ostree) failed:
$(cat "$TMP/out")"
assert_logged '^sudo rpm-ostree install --idempotent .*hyprland'
assert_not_logged '^dnf'
assert_not_logged '^curl'
grep -qi 'reboot' "$TMP/out" || fail "ostree path must tell the user to reboot"

# --- desktop/install.sh with a COPR list: dnf's copr plugin, or the .repo file on ostree
setup_env
mock dnf
mock systemctl
mock flatpak
mock sudo 'exec "$@"'
printf 'solopasha/hyprland # why\n' >"$TMP/coprs.txt"
WARDOS_COPRS_FILE=$TMP/coprs.txt bash "$repo/desktop/install.sh" --destdir "$TMP/root" >"$TMP/out" 2>&1 || fail "install.sh (coprs) failed:
$(cat "$TMP/out")"
assert_logged '^sudo dnf -y install dnf5-plugins$'
assert_logged '^sudo dnf -y copr enable solopasha/hyprland$'
setup_env
mock rpm-ostree
mock systemctl
mock flatpak
mock curl
mock sudo 'exec "$@"'
touch "$TMP/ostree-booted"
printf 'solopasha/hyprland # why\n' >"$TMP/coprs.txt"
WARDOS_COPRS_FILE=$TMP/coprs.txt WARDOS_OSTREE_MARKER=$TMP/ostree-booted bash "$repo/desktop/install.sh" --destdir "$TMP/root" >"$TMP/out" 2>&1 || fail "install.sh (ostree, coprs) failed:
$(cat "$TMP/out")"
assert_logged '^sudo curl -fsSL -o /etc/yum.repos.d/_copr_solopasha-hyprland.repo https://copr.fedorainfracloud.org/coprs/solopasha/hyprland/repo/fedora-'"$rel"'/solopasha-hyprland-fedora-'"$rel"'.repo$'

# --- desktop/install.sh --dry-run runs nothing -------------------------------------
setup_env
mock dnf
mock systemctl
mock flatpak
mock sudo 'exec "$@"'
bash "$repo/desktop/install.sh" --dry-run >"$TMP/out"
[[ ! -s "$MOCK_LOG" ]] || fail "--dry-run must not run commands; log:
$(cat "$MOCK_LOG")"
grep -q 'dnf install' "$TMP/out" || fail "--dry-run must print the dnf command"
grep -q 'install-desktop.sh' "$TMP/out" || fail "--dry-run must print the install-desktop step"
bash "$repo/desktop/install.sh" --help | grep -q 'install.sh' || fail "--help prints usage"
! bash "$repo/desktop/install.sh" --bogus 2>/dev/null || fail "unknown flags must fail"

# --- desktop/install.sh: neither dnf nor rpm-ostree ---------------------------------
setup_env
mock sudo 'exec "$@"'
PATH="$MOCK_DIR:/usr/bin:/bin" bash "$repo/desktop/install.sh" --destdir "$TMP/root" >"$TMP/out" 2>&1 && fail "must fail without dnf or rpm-ostree"
grep -q 'Fedora' "$TMP/out" || fail "must say it needs Fedora"

# --- image/flathub.sh: remote, then the default list ---------------------------------
setup_env
mock flatpak
printf '# apps\norg.signal.Signal\n\ncom.spotify.Client # music\n' >"$TMP/flatpaks.txt"
bash "$repo/image/flathub.sh" "$TMP/flatpaks.txt"
assert_logged '^flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo$'
assert_logged '^flatpak install -y --noninteractive flathub org.signal.Signal com.spotify.Client$'
: >"$MOCK_LOG"
bash "$repo/image/flathub.sh" "$TMP/no-such-list"
assert_logged '^flatpak remote-add'
assert_not_logged '^flatpak install'

# --- image/check-packages.sh: exact names, diffed against what dnf resolved -----------
setup_env
printf '# manifest\nhyprland   # compositor\nfoot\n\nnope-not-a-package # unverified\n' >"$TMP/packages.txt"
mock docker 'printf "%s\n" hyprland foot ""'
bash "$repo/image/check-packages.sh" --file "$TMP/packages.txt" --coprs "$TMP/no-coprs" >"$TMP/out" 2>&1 && fail "a missing name must fail"
assert_logged '^docker run --rm quay.io/fedora/fedora:'"$rel"' bash -c .*repoquery.* -- 0 foot hyprland nope-not-a-package$'
grep -q '^  nope-not-a-package$' "$TMP/out" || fail "missing name not listed:
$(cat "$TMP/out")"
! grep -q '^  hyprland$' "$TMP/out" || fail "resolved name listed as missing"
mock docker 'printf "%s\n" hyprland foot nope-not-a-package'
printf '# coprs\nowner/project # why\n\n' >"$TMP/coprs.txt"
bash "$repo/image/check-packages.sh" --file "$TMP/packages.txt" --coprs "$TMP/coprs.txt" >"$TMP/out" 2>&1 || fail "all names resolve:
$(cat "$TMP/out")"
grep -q 'all 3 names exist' "$TMP/out" || fail "success line missing"
# The COPRs precede the names, counted, and are enabled with dnf5's copr plugin.
assert_logged '^docker run --rm quay.io/fedora/fedora:'"$rel"' bash -c .*dnf5-plugins.*echo .copr enable .*dnf -y -q copr enable.* -- 1 owner/project foot hyprland nope-not-a-package$'
# --dry-run prints the command and runs nothing; --release changes the container tag.
: >"$MOCK_LOG"
bash "$repo/image/check-packages.sh" --file "$TMP/packages.txt" --release 99 --dry-run >"$TMP/out"
[[ ! -s "$MOCK_LOG" ]] || fail "--dry-run ran docker"
grep -q 'fedora:99' "$TMP/out" || fail "--release not honoured"
mock podman 'printf "%s\n" hyprland foot nope-not-a-package'
CONTAINER_RUNTIME=podman bash "$repo/image/check-packages.sh" --file "$TMP/packages.txt" >/dev/null
assert_logged '^podman run'
# The real manifest parses and every name is a plain package name (no spaces, no versions).
bash "$repo/image/check-packages.sh" --dry-run >"$TMP/out"
grep -q "fedora:$rel " "$TMP/out" || fail "release not derived from the Containerfile:
$(cat "$TMP/out")"
! sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$repo/image/packages.txt" | grep -Ev '^[A-Za-z0-9._+-]+$' || fail "packages.txt has a bad name"
! sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$repo/image/coprs.txt" | grep -Ev '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || fail "coprs.txt has a bad entry"

# --- image/disk.sh: --user and --luks write the bootc-image-builder config -----------
setup_env
out=$TMP/disk
bash "$repo/image/disk.sh" --type qcow2 --user wardos --password 'p&ss/w.rd' --output "$out" --dry-run >"$TMP/out"
assert_file "$out/config.toml"
assert_contains "$out/config.toml" '[[customizations.user]]'
assert_contains "$out/config.toml" 'name = "wardos"'
assert_contains "$out/config.toml" 'password = "p&ss/w.rd"'
assert_contains "$out/config.toml" 'groups = ["wheel"]'
assert_eq "$(stat -c %a "$out/config.toml")" 600
! grep -q 'p&ss/w.rd' "$TMP/out" || fail "dry-run output must not show the password"
grep -q -- '--config /config.toml' "$TMP/out" || fail "generated config not passed to the builder"
# --luks: the installer's kickstart, user inside it, no [[customizations.user]].
echo 'ssh-ed25519 AAAATEST key@test' >"$TMP/key.pub"
WARDOS_PASSWORD=secret bash "$repo/image/disk.sh" --type iso --luks --user wardos --ssh-key "$TMP/key.pub" --output "$out" --dry-run >"$TMP/out"
assert_contains "$out/config.toml" '[customizations.installer.kickstart]'
assert_contains "$out/config.toml" 'autopart --noswap --type=btrfs --encrypted'
assert_contains "$out/config.toml" 'user --name=wardos --groups=wheel --password=secret --plaintext'
assert_contains "$out/config.toml" 'sshkey --username=wardos "ssh-ed25519 AAAATEST key@test"'
assert_contains "$out/config.toml" 'rootpw --lock'
! grep -q 'customizations.user' "$out/config.toml" || fail "--luks must not also use customizations.user"
! grep -q 'secret' "$TMP/out" || fail "dry-run output must not show WARDOS_PASSWORD"
# Refusals: LUKS on qcow2, a user with no way in, --config together with --user.
! bash "$repo/image/disk.sh" --type qcow2 --luks --output "$out" --dry-run 2>/dev/null || fail "--luks on qcow2 must fail"
! bash "$repo/image/disk.sh" --type qcow2 --user wardos --output "$out" --dry-run 2>/dev/null || fail "--user without a password or key must fail"
! bash "$repo/image/disk.sh" --type iso --user wardos --password x --config "$out/config.toml" --output "$out" --dry-run 2>/dev/null || fail "--config with --user must fail"
# Without --user/--luks nothing is generated and no --config is passed.
rm -rf "$out"
bash "$repo/image/disk.sh" --type iso --output "$out" --dry-run >"$TMP/out"
assert_missing "$out/config.toml"
! grep -q -- '--config' "$TMP/out" || fail "no config expected"

# --- image/check-packages.sh --discover: COPR projects and their chroots, from the API ----
setup_env
mock curl 'case "$*" in
  *"project/search?query=hyprland"*) printf %s "{\"items\":[{\"full_name\":\"someone/hyprland\",\"chroot_repos\":{\"fedora-rawhide-x86_64\":\"u\",\"fedora-'"$rel"'-x86_64\":\"u\"}},{\"full_name\":\"other/hypr\",\"chroot_repos\":{\"fedora-rawhide-x86_64\":\"u\"}}]}" ;;
  *"project/search"*) printf %s "{\"items\":[]}" ;;
  *"ownername=solopasha&projectname=hyprland"*) printf %s "{\"full_name\":\"solopasha/hyprland\",\"chroot_repos\":{\"fedora-rawhide-x86_64\":\"u\"}}" ;;
  *) exit 22 ;;
esac'
bash "$repo/image/check-packages.sh" --discover hyprland nothing >"$TMP/out" 2>&1 || fail "--discover must not fail:
$(cat "$TMP/out")"
assert_contains "$TMP/out" "  someone/hyprland: fedora-$rel-x86_64"
assert_contains "$TMP/out" "  other/hypr: no fedora-"
assert_contains "$TMP/out" "  no project mentions nothing"
assert_contains "$TMP/out" "  solopasha/hyprland: no fedora-"
assert_contains "$TMP/out" "  dejan/lazygit: not found"
assert_logged '^curl -fsSL https://copr.fedorainfracloud.org/api_3/project/search\?query=hyprland$'
