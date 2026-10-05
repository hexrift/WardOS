#!/usr/bin/env bash
# The README capture (desktop/capture, issue #84), checked without a compositor: the scene
# table is well-formed and matches capture.sh's scene functions and the storyboard's
# durations, every package is the image's or says why not, every wardos-* command the
# capture drives exists, the workflow and refresh.sh agree on names, and refresh.sh takes
# the GIF from the right run. The capture itself runs in CI (desktop-capture.yml).
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

cap="$test_root/desktop/capture"
table="$cap/scenes.tsv"
script="$cap/capture.sh"
story="$test_root/assets/storyboard/story.py"
workflow="$test_root/.github/workflows/desktop-capture.yml"
assert_file "$table"
assert_file "$script"
assert_file "$workflow"

"$script" --help | grep -q 'capture.sh OUT' || fail "capture.sh --help prints its usage"
status=0
"$script" >/dev/null 2>&1 || status=$?
[[ $status -eq 2 ]] || fail "capture.sh without OUT exits 2, got $status"

# --- scenes.tsv ---------------------------------------------------------------------
ids=()
total=0
while IFS= read -r line; do
  [[ -z $line || $line == \#* ]] && continue
  IFS=$'\t' read -r -a f <<<"$line"
  [[ ${#f[@]} -eq 5 ]] || fail "scenes.tsv: five tab-separated fields, got ${#f[@]}: $line"
  id=${f[0]} ms=${f[1]} need=${f[2]} cap_story=${f[3]} what=${f[4]}
  [[ $id =~ ^[a-z]+$ ]] || fail "scenes.tsv: scene id '$id' is not lower-case letters"
  for seen in "${ids[@]}"; do [[ $seen != "$id" ]] || fail "scenes.tsv: $id twice"; done
  ids+=("$id")
  if [[ ! $ms =~ ^[0-9]+$ ]] || ((ms < 500 || ms > 5000)); then fail "scenes.tsv: $id shows for '$ms' ms (500..5000)"; fi
  total=$((total + ms))
  [[ $need == required || $need == optional ]] || fail "scenes.tsv: $id need is '$need'"
  [[ -n $what ]] || fail "scenes.tsv: $id says nothing about what is on screen"
  grep -q "^scene_$id() " "$script" || fail "capture.sh has no scene_$id"
  if [[ $cap_story != - && -f $story ]]; then
    grep -qF "\"$cap_story\", $ms)" "$story" ||
      fail "scenes.tsv: $id stands in for the storyboard frame '$cap_story', which story.py does not show for $ms ms"
  fi
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
      grep -qx "name = \"$cmd\"" "$test_root"/desktop/*/Cargo.toml "$test_root"/crates/*/Cargo.toml ||
        fail "no crate builds $cmd"
      ;;
    wardos-*) [[ -f "$test_root/desktop/bin/$cmd" ]] || fail "capture.sh needs $cmd, which desktop/bin does not have" ;;
  esac
done
while read -r cmd; do
  grep -qx -- "$cmd" <<<"$cmds" || fail "capture.sh starts $cmd without checking for it first"
done < <(grep -oE '(hypr_run|menu_open) [a-z-]+' "$script" | awk '{ print $2 }' | sort -u)

# --- workflow and refresh.sh agree -------------------------------------------------------
for want in desktop/capture/packages.txt desktop/capture/capture.sh image/coprs.txt \
  image/install-desktop.sh 'name: wardos-desktop-capture$' 'container: fedora:'; do
  grep -qE -- "$want" "$workflow" || fail "desktop-capture.yml does not mention $want"
done
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
python3 "$cap/assemble.py" check "$frames/01-${ids[0]}.png" || fail "assemble.py check refused a real-looking shot"
if python3 "$cap/assemble.py" check "$TMP/flat.png" 2>/dev/null; then fail "assemble.py check must refuse a flat frame"; fi
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
