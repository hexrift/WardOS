#!/usr/bin/env bash
# The README capture (desktop/capture, issue #84), checked without a compositor: the scene
# table is well-formed and matches capture.sh's scene functions, every package is the
# image's or says why not, every wardos-* command the
# capture drives exists, the workflow, ci-run.sh and refresh.sh agree on names and on the
# render node, and refresh.sh takes the GIF from the right run. The capture itself runs
# in CI (desktop-capture.yml).
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

cap="$test_root/desktop/capture"
table="$cap/scenes.tsv"
script="$cap/capture.sh"
ci_run="$cap/ci-run.sh"
workflow="$test_root/.github/workflows/desktop-capture.yml"
docs="$test_root/docs/desktop.md"
assert_file "$table"
assert_file "$script"
assert_file "$ci_run"
assert_file "$workflow"

"$script" --help | grep -q 'capture.sh OUT' || fail "capture.sh --help prints its usage"
status=0
"$script" >/dev/null 2>&1 || status=$?
[[ $status -eq 2 ]] || fail "capture.sh without OUT exits 2, got $status"
"$ci_run" --help | grep -q 'ci-run.sh BINARIES OUT' || fail "ci-run.sh --help prints its usage"
status=0
"$ci_run" only-one >/dev/null 2>&1 || status=$?
[[ $status -eq 2 ]] || fail "ci-run.sh without BINARIES and OUT exits 2, got $status"
if [[ $(id -u) -ne 0 ]]; then
  status=0
  "$ci_run" "$TMP" "$TMP/out" >/dev/null 2>&1 || status=$?
  [[ $status -eq 1 ]] || fail "ci-run.sh refuses to run as an unprivileged user, got $status"
fi

# --- scenes.tsv ---------------------------------------------------------------------
ids=()
total=0
while IFS= read -r line; do
  [[ -z $line || $line == \#* ]] && continue
  IFS=$'\t' read -r -a f <<<"$line"
  [[ ${#f[@]} -eq 4 ]] || fail "scenes.tsv: four tab-separated fields, got ${#f[@]}: $line"
  id=${f[0]} ms=${f[1]} need=${f[2]} what=${f[3]}
  [[ $id =~ ^[a-z]+$ ]] || fail "scenes.tsv: scene id '$id' is not lower-case letters"
  for seen in "${ids[@]}"; do [[ $seen != "$id" ]] || fail "scenes.tsv: $id twice"; done
  ids+=("$id")
  if [[ ! $ms =~ ^[0-9]+$ ]] || ((ms < 500 || ms > 5000)); then fail "scenes.tsv: $id shows for '$ms' ms (500..5000)"; fi
  total=$((total + ms))
  [[ $need == required || $need == optional ]] || fail "scenes.tsv: $id need is '$need'"
  [[ -n $what ]] || fail "scenes.tsv: $id says nothing about what is on screen"
  grep -q "^scene_$id() " "$script" || fail "capture.sh has no scene_$id"
done <"$table"
[[ ${#ids[@]} -ge 8 ]] || fail "scenes.tsv: ${#ids[@]} scenes"
[[ $(awk -F'\t' '!/^#/ && NF { print $3; exit }' "$table") == required ]] || fail "the first scene must be required"
((total <= 30000)) || fail "the capture runs ${total} ms; keep the GIF under 30 s"
while read -r fn; do
  id=${fn#*_}
  printf '%s\n' "${ids[@]}" | grep -qx "$id" || fail "capture.sh defines $fn, but scenes.tsv has no scene $id"
done < <(grep -oE '^(scene|leave)_[a-z]+' "$script")

# --- packages.txt -------------------------------------------------------------------
image_pkgs=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$test_root/image/packages.txt")
n=0
while IFS= read -r line; do
  name=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' <<<"$line")
  [[ -n $name ]] || continue
  n=$((n + 1))
  if grep -qx -- "$name" <<<"$image_pkgs"; then
    [[ $line != *"# capture:"* ]] || fail "packages.txt: $name is in image/packages.txt; drop its '# capture:' note"
  else
    [[ $line == *"# capture: "?* ]] || fail "packages.txt: $name is not in image/packages.txt and does not say why the capture needs it (# capture: …)"
  fi
done <"$cap/packages.txt"
((n > 0)) || fail "packages.txt names nothing"
for pkg in hyprland waybar mako fuzzel foot grim; do
  grep -qx "$pkg" < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$cap/packages.txt") || fail "packages.txt lacks $pkg"
done

# --- the commands the capture drives exist -------------------------------------------
# capture.sh checks its PATH for every command it needs before it starts; each wardos-*
# one is in desktop/bin, each ward binary is built by the workflow, and everything it
# starts through the compositor is on that list.
cmds=$(awk '/^for cmd in /{f=1} f{print} f && /; do$/{exit}' "$script" |
  sed -e 's/^for cmd in //' -e 's/; do$//' -e 's/\\$//' | tr -s ' ' '\n' | sed '/^$/d')
[[ -n $cmds ]] || fail "capture.sh checks no commands before it starts"
for cmd in $cmds; do
  case "$cmd" in
    wardos-theme-render | ward | wardd | ward-shell)
      grep -q "target/release/$cmd$" "$workflow" || fail "desktop-capture.yml does not hand $cmd to the capture"
      grep -q "\"\$bins\"/$cmd\b" "$ci_run" || fail "ci-run.sh does not install $cmd"
      grep -qx "name = \"$cmd\"" "$test_root"/desktop/*/Cargo.toml "$test_root"/crates/*/Cargo.toml ||
        fail "no crate builds $cmd"
      ;;
    wardos-*) [[ -f "$test_root/desktop/bin/$cmd" ]] || fail "capture.sh needs $cmd, which desktop/bin does not have" ;;
  esac
done
while read -r cmd; do
  grep -qx -- "$cmd" <<<"$cmds" || fail "capture.sh starts $cmd without checking for it first"
done < <(grep -oE '(hypr_run|menu_open) [a-z-]+' "$script" | awk '{ print $2 }' | sort -u)

# --- workflow, ci-run.sh and refresh.sh agree --------------------------------------------
# The job runs on the host so it can load vkms and give its card to the Fedora container
# (a job container starts before any step could); ci-run.sh installs the stack and runs
# seatd for the seat aquamarine opens the card through; capture.sh picks the card by
# driver and wants the DRM backend, not headless only.
# shellcheck disable=SC2016  # grep patterns, not expansions
for want in 'CAPTURE_DRM_DRIVER: vkms' 'before=\(/sys/class/drm/card\*\)' 'modprobe "\$CAPTURE_DRM_DRIVER"' 'echo "card=\$node" >>"\$GITHUB_OUTPUT"' \
  'CAPTURE_DRM_CARD: \$\{\{ steps.drm.outputs.card \}\}' '--device /dev/dri' '-e CAPTURE_DRM_DRIVER -e CAPTURE_DRM_CARD' \
  'image/Containerfile' 'desktop/capture/ci-run.sh /w/capture-binaries /w/capture-out' \
  'name: wardos-desktop-capture$' 'name: wardos-desktop-capture-logs$'; do
  grep -qE -- "$want" "$workflow" || fail "desktop-capture.yml does not mention $want"
done
! grep -qE '^ *container:' "$workflow" || fail "desktop-capture.yml must not use a job container: the DRM node is loaded on the host first"
# The inline GIF: a workflow_dispatch input, off by default, never on a pull request; the
# markers and the size/sha line a host without artifact access decodes against.
# shellcheck disable=SC2016  # literal fragments of the workflow, not expansions
for want in 'inline_gif:' 'type: boolean' 'default: false' \
  "if: github.event_name == 'workflow_dispatch' && inputs.inline_gif" 'base64 -w0 "$gif"' \
  'echo "-----BEGIN WARDOS-DESKTOP-GIF-----"' 'echo "-----END WARDOS-DESKTOP-GIF-----"' \
  'echo "size=$size sha256=$(sha256sum "$gif" | cut -d'"'"' '"'"' -f1)"' 'size > 2 * 1024 * 1024'; do
  grep -qF -- "$want" "$workflow" || fail "desktop-capture.yml does not have: $want"
done
grep -q 'BEGIN WARDOS-DESKTOP-GIF' "$docs" || fail "docs/desktop.md does not describe the inline GIF markers"
# shellcheck disable=SC2016  # grep patterns, not expansions
for want in desktop/capture/packages.txt image/coprs.txt image/install-desktop.sh 'SEATD_VTBOUND=0 seatd -u wardos -g wardos' \
  'runuser -u wardos' 'LIBSEAT_BACKEND=seatd' 'CAPTURE_DRM_CARD="\$\{CAPTURE_DRM_CARD:-\}"' desktop/capture/capture.sh \
  'chmod 0666 "\$\{nodes' 'kill "\$seatd_pid"' 'trap hand_back EXIT' \
  'dbus-daemon --system --nofork --nopidfile' '/run/dbus/system_bus_socket' 'kill "\$dbus_pid"'; do
  grep -qE -- "$want" "$ci_run" || fail "ci-run.sh does not mention $want"
done
# shellcheck disable=SC2016  # grep patterns, not expansions
for want in 'AQ_DRM_DEVICES=\$CAPTURE_DRM_CARD' 'AQ_DRM_DEVICES=\$\(drm_card "\$driver"\)' 'export AQ_DRM_DEVICES' 'GBM_ALWAYS_SOFTWARE=1' 'LIBGL_ALWAYS_SOFTWARE=1' \
  'AQ_TRACE=1' 'HYPRLAND_TRACE=1' 'output create headless' 'monitor = , 1920x1080@60'; do
  grep -qE -- "$want" "$script" || fail "capture.sh does not mention $want"
done
# The clients start from the shipped autostart.conf, each exec-once logging to its own
# file and its exit status after it (a killed Waybar leaves no other trace), Waybar at
# debug level and hypridle's line a no-op, both for the capture only; a failed scene's
# shot and every scene's shot are described; the failure output has the client logs,
# hyprctl, the processes and Hyprland's log without TRACE. The shell worker is never
# started by hand: with no session it logs its "no session" line without pause (it is
# systemd's to restart every two seconds), which filled a disk.
trace_filter="grep -v '\\[TRACE\\]'"
# shellcheck disable=SC2016  # literal fragments of the script, not expansions
for want in 'exec-once = " cmd " >>" logs "/" name ".log 2>&1; echo \"exited $?\" >>" logs "/" name ".log"' \
  'if (cmd == "waybar") cmd = "waybar -l debug"' 'if (name == "hypridle") { print "exec-once = true # hypridle' \
  'assemble.py" check "$png"' 'assemble.py" describe "$logs/not-on-screen-$id.png"' 'ps -o pid,ppid,stat,etime,cmd -u' \
  "$trace_filter" 'layers [$(layers_seen)]' 'hyprctl dismissnotify' \
  'expect[tokyo]='"'"'--region 0,0,1920,32 --dominant "$(theme_token WARDOS_GROUND)"'"'"'' \
  'bar_ground_is "$(theme_token WARDOS_GROUND)"' 'pid_gone "$swaybg_was"' 'wallpaper_is_not "$sha_was"'; do
  grep -qF -- "$want" "$script" || fail "capture.sh does not have: $want"
done
for pkg in wl-clipboard cliphist dbus-daemon dbus-tools; do
  grep -qx "$pkg" < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$cap/packages.txt") || fail "packages.txt lacks $pkg (the shipped exec-once lines and the buses need it)"
done
! grep -qE '^[^#]*ward-shell worker' "$script" || fail "capture.sh must not start ward-shell worker itself (a tight loop with no session)"
! grep -q 'HYPRLAND_HEADLESS_ONLY=1' "$script" || fail "capture.sh must not set HYPRLAND_HEADLESS_ONLY: the DRM backend on vkms is the allocator"
! grep -qE 'hyprctl [a-z]+ -j [^|]*\| *jq' "$script" || fail "capture.sh pipes hyprctl straight into jq; use hypr_json, which checks for JSON first"
! grep -q 'layer_recreated' "$script" || fail "capture.sh waits on the bar's layer addresses changing; Waybar may re-create its surface at the same address (run 9), wait on the bar's ground instead"
grep -qx 'seatd' < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$cap/packages.txt") || fail "packages.txt lacks seatd"

# drm_is, on a sysfs stand-in: a card is vkms's by driver name, by its device path (the
# faux bus of Linux 6.16+, where the driver reads faux_driver) or by its uevent, and the
# runner's own adapter is none of those.
sys="$TMP/sys/class/drm"
for card in card0 card1 card2 card3; do mkdir -p "$sys/$card"; done
mkdir -p "$TMP/sys/devices/faux/vkms" "$TMP/sys/bus/faux/drivers/faux_driver" "$TMP/sys/devices/platform/vkms" \
  "$TMP/sys/bus/platform/drivers/vkms" "$TMP/sys/devices/pci0000:00/0000:00:08.0" "$TMP/sys/bus/pci/drivers/hyperv_drm" "$TMP/sys/devices/odd"
ln -s ../../../../bus/faux/drivers/faux_driver "$TMP/sys/devices/faux/vkms/driver"
ln -s ../../../../bus/platform/drivers/vkms "$TMP/sys/devices/platform/vkms/driver"
ln -s ../../../../bus/pci/drivers/hyperv_drm "$TMP/sys/devices/pci0000:00/0000:00:08.0/driver"
ln -s ../../../devices/faux/vkms "$sys/card0/device"
ln -s ../../../devices/pci0000:00/0000:00:08.0 "$sys/card1/device"
ln -s ../../../devices/platform/vkms "$sys/card2/device"
ln -s ../../../devices/odd "$sys/card3/device"
printf 'DRIVER=hyperv_drm\n' >"$TMP/sys/devices/pci0000:00/0000:00:08.0/uevent"
printf 'MODALIAS=faux:vkms\n' >"$TMP/sys/devices/odd/uevent"
probe() { # probe CARD DRIVER: drm_is with the stand-in sysfs
  (
    # shellcheck disable=SC1090  # the functions of capture.sh, up to its first command
    eval "$(sed -n '/^drm_of() {/,/^}/p; /^drm_is() {/,/^}/p' "$script" | sed "s|/sys/class/drm|$sys|")"
    drm_is "/dev/dri/$1" "$2"
  )
}
probe card0 vkms || fail "drm_is misses the faux-bus vkms card (driver faux_driver, device …/faux/vkms)"
probe card2 vkms || fail "drm_is misses the platform-bus vkms card (driver vkms)"
probe card3 vkms || fail "drm_is misses a card whose uevent says MODALIAS=…vkms"
if probe card1 vkms; then fail "drm_is takes the hyperv_drm adapter for vkms"; fi
grep -q -- '--workflow desktop-capture.yml' "$cap/refresh.sh" || fail "refresh.sh names another workflow"
grep -q -- '--name wardos-desktop-capture' "$cap/refresh.sh" || fail "refresh.sh names another artifact"
! grep -qE 'contents: *write' "$workflow" || fail "desktop-capture.yml must not write to the repository"

# --- refresh.sh -------------------------------------------------------------------------
# shellcheck disable=SC2016  # the mock body expands when the mock runs
mock gh 'if [[ "$1 $2" == "run list" ]]; then printf "%s\n" "${GH_RUN:-}"; elif [[ "$1 $2" == "run download" ]]; then while [[ $# -gt 0 ]]; do [[ $1 == --dir ]] && d=$2; shift; done; printf "%s" "${GH_GIF:-GIF89a-capture}" >"$d/wardos-desktop.gif"; fi'
out="$TMP/assets/wardos-desktop.gif"
"$cap/refresh.sh" --help | grep -q -- '--ref REF' || fail "refresh.sh --help prints its usage"

GH_RUN=4242 "$cap/refresh.sh" --out "$out" >/dev/null
assert_logged '^gh run list --workflow desktop-capture.yml --branch main --status success '
assert_logged '^gh run download 4242 --name wardos-desktop-capture --dir '
assert_eq "$(cat "$out")" "GIF89a-capture"

: >"$MOCK_LOG"
GH_GIF=GIF89a-v1 "$cap/refresh.sh" --run 77 --repo hexrift/WardOS --out "$out" >/dev/null
assert_not_logged '^gh run list'
assert_logged '^gh run download 77 --repo hexrift/WardOS --name wardos-desktop-capture '
assert_eq "$(cat "$out")" "GIF89a-v1"

: >"$MOCK_LOG"
GH_RUN=9 "$cap/refresh.sh" --ref v0.5.0 --out "$out" >/dev/null
assert_logged '^gh run list --workflow desktop-capture.yml --branch v0.5.0 '

before=$(cat "$out")
if GH_RUN="" "$cap/refresh.sh" --out "$out" 2>/dev/null; then fail "refresh.sh with no successful run must fail"; fi
if GH_RUN=5 GH_GIF='<html>' "$cap/refresh.sh" --out "$out" 2>/dev/null; then fail "refresh.sh must refuse a file that is not a GIF"; fi
assert_eq "$(cat "$out")" "$before"
if "$cap/refresh.sh" --run 'latest;x' --out "$out" 2>/dev/null; then fail "refresh.sh must refuse a non-numeric run id"; fi

# --- assemble.py, where Pillow is installed (the capture job has it) ---------------------
if ! python3 -c 'import PIL' 2>/dev/null; then
  echo "skip desktop-capture.test.sh assemble.py part: Pillow not installed (the capture job runs it for real)"
  exit 0
fi
frames="$TMP/frames"
mkdir -p "$frames"
python3 - "$table" "$frames" <<'EOF'
import sys
from PIL import Image, ImageDraw
rows = [l.split("\t") for l in open(sys.argv[1], encoding="utf-8") if l.strip() and not l.startswith("#")]
for i, r in enumerate(rows, 1):
    if r[2] == "optional":
        continue
    img = Image.new("RGB", (1920, 1080), (14, 15, 17))
    ImageDraw.Draw(img).rectangle((0, 0, 100 * i, 31), fill=(127, 161, 195))
    img.save(f"{sys.argv[2]}/{i:02d}-{r[0]}.png")
Image.new("RGB", (1920, 1080), (0, 0, 0)).save(f"{sys.argv[2]}/../flat.png")
EOF
line=$(python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png") || fail "assemble.py check refused a real-looking shot"
[[ $line == *"1920x1080, 2 colours, dominant #0e0f11 ("* ]] || fail "assemble.py check describes the shot: $line"
if python3 "$cap/assemble.py" check "$TMP/flat.png" 2>/dev/null; then fail "assemble.py check must refuse a flat frame"; fi
if python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" --not-dominant '#0E0F11' >/dev/null 2>&1; then
  fail "assemble.py check --not-dominant must refuse a shot still dominated by that colour"
fi
python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" --not-dominant '#16161e' >/dev/null || fail "assemble.py check --not-dominant passes a shot dominated by another colour"
# The region: the frame's bar strip is 100 px of accent on the ground; the strip alone is
# the accent, the whole bar row is not.
line=$(python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" --region 0,0,100,32 --dominant '#7FA1C3') || fail "assemble.py check --region --dominant refused the accent strip"
[[ $line == *"region 0,0 100x32: 1 colours, dominant #7fa1c3 (100%)"* ]] || fail "assemble.py check describes the region: $line"
if python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" --region 0,0,1920,32 --dominant '#7FA1C3' >/dev/null 2>&1; then
  fail "assemble.py check --region --dominant must refuse a region dominated by another colour"
fi
if python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" --region 0,0,100 >/dev/null 2>&1; then fail "assemble.py check takes a region of four numbers"; fi
line=$(python3 "$cap/assemble.py" describe "$TMP/flat.png") || fail "assemble.py describe never fails"
[[ $line == *"one flat colour, dominant #000000 (100%)"* ]] || fail "assemble.py describe names the flat colour: $line"
python3 "$cap/assemble.py" gif "$table" "$frames" "$TMP/out.gif" >/dev/null
want=$(awk -F'\t' '!/^#/ && NF && $3 == "required" { printf "%s%s", s, $2; s = "," }' "$table")
got=$(python3 -c '
import sys
from PIL import Image
im, d = Image.open(sys.argv[1]), []
try:
    while True:
        d.append(str(im.info["duration"]))
        im.seek(im.tell() + 1)
except EOFError:
    pass
print(",".join(d), im.size[0], im.size[1])' "$TMP/out.gif")
assert_eq "$got" "$want 1280 720"
rm "$frames/02-${ids[1]}.png"
if python3 "$cap/assemble.py" gif "$table" "$frames" "$TMP/out.gif" 2>/dev/null; then
  fail "assemble.py gif must fail when a required scene has no shot"
fi
