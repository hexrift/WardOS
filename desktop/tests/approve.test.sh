#!/usr/bin/env bash
# wardos-approve (docs/design-language.md §10, ADR-0016, ADR-0019): the watch path turns
# each pending approval into a mako notification with the three blocks (destination,
# the agent's claim labelled as such, what Ward will allow) and the three actions, and
# relays the chosen action; the interactive path picks an approval, shows the blocks,
# and answers it with y / s / n. Nothing the agent wrote reaches the body unescaped.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

approve=$WARDOS_ROOT/bin/wardos-approve
line12='{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1,"agent":"claude","session":"sess_a"}'
# The agent's claim carries markup and a fake row: both must arrive escaped.
line13='{"id":13,"tool":"WebFetch","summary":"https://api.github.com/x?<b>y</b>","claim":"WebFetch https://api.github.com/x?<b>y</b>\nCredential   root & all","authority":{"rule":"step-through: pause before network","destination":"api.github.com","network":"reachable · restricted (dev)","method":"GET","credential":"GitHub · contents:read, issues:read","repository":"hexrift/WardOS","lifetime":null},"requested_at_unix_ms":2,"agent":"claude","session":"sess_a"}'
export LINE12=$line12 LINE13=$line13

# --- --help --------------------------------------------------------------------
"$approve" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$approve" --help | grep -q 'wardos-approve --watch' || fail "--help names --watch"
"$approve" --help | grep -q 'WARD WILL ALLOW' || fail "--help names the three blocks"

# --- --watch: one notification per pending approval, the action relayed --------
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --follow "*) printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The first notification is answered with "Allow session", the second is dismissed.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in *"/work/src/lib.rs"*) echo session ;; *) exit 0 ;; esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session pending --json --follow /home/dev/payments-api$'
# The layout of §10: the title, then the three blocks, headers dim, the target in <tt>.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests <span alpha="39322">DESTINATION</span>$'
assert_logged '^<tt>/work/src/lib.rs</tt>$'
assert_logged '^<span alpha="39322">REQUESTED BY AGENT</span>$'
assert_logged '^Write /work/src/lib.rs$'
assert_logged '^<span alpha="39322">WARD WILL ALLOW</span>$'
assert_logged '^Network      none$'
assert_logged '^Method       write$'
assert_logged '^Credential   none$'
assert_logged '^Repository   none$'
assert_logged '^Lifetime     once \(y\) · session \(s\)$'
assert_not_logged 'Reason  '
assert_not_logged 'Scope   '
# The second approval: Ward's rows come from the daemon, the agent's claim is escaped
# so its markup and its fake "Credential" row cannot pose as Ward's.
assert_logged '^<tt>api.github.com</tt>$'
assert_logged '^WebFetch https://api.github.com/x\?&lt;b&gt;y&lt;/b&gt;\\nCredential   root &amp; all$'
assert_not_logged '<b>y</b>'
assert_logged '^Network      reachable · restricted \(dev\)$'
assert_logged '^Method       GET$'
assert_logged '^Credential   GitHub · contents:read, issues:read$'
assert_logged '^Repository   hexrift/WardOS$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'
assert_not_logged '^ward session approve --session sess_a 13'

# A denial relays as deny; an unknown action is left to the daemon's timeout.
: >"$MOCK_LOG"
mock notify-send 'case "$*" in *"/work/src/lib.rs"*) echo deny ;; *) echo bogus ;; esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session approve --session sess_a 12 deny$'
assert_not_logged '^ward session approve --session sess_a 13'

# --- interactive: one pending approval is picked, shown, the menu answers y / s / n ---
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n" "$LINE12" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
out=$(WARDOS_MENU_CHOICE=y "$approve")
assert_logged '^ward session pending --json '"$PWD"'$'
assert_logged '^ward session approve --session sess_a 12 allow$'
assert_not_logged '^wardos-menu-select'
printf '%s\n' "$out" | grep -q '^Claude requests · Write$' || fail "the terminal names who asks: $out"
printf '%s\n' "$out" | grep -q '^DESTINATION$' || fail "the terminal shows the blocks: $out"
printf '%s\n' "$out" | grep -q '^  /work/src/lib.rs$' || fail "the destination, plain: $out"
printf '%s\n' "$out" | grep -q '^REQUESTED BY AGENT$' || fail "the claim is labelled: $out"
printf '%s\n' "$out" | grep -q '^  Method       write$' || fail "the authority rows: $out"
printf '%s\n' "$out" | grep -q '<tt>' && fail "no markup in the terminal: $out"

# The menu is wardos-menu-select when it exists; s is the session grant.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE=s "$approve" >/dev/null
assert_logged '^wardos-menu-select --prompt Approve$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'

# A cancelled menu answers nothing (the daemon's timeout denies).
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='' "$approve" >/dev/null && fail "a cancelled menu is not success"
assert_not_logged '^ward session approve'

# --- interactive: several pending, the approval is picked first --------------------
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/wardos-menu-select"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_MENU_CHOICE=13 "$approve" 13 n
assert_logged '^ward session approve --session sess_a 13 deny$'
: >"$MOCK_LOG"
"$approve" 99 y && fail "an id that is not pending is an error"
assert_not_logged '^ward session approve'
: >"$MOCK_LOG"
# With no id the first menu picks the approval by its id line, then the answer.
# Both menus read the same choice with the stdin backend, so pick 13 and give n.
WARDOS_MENU_CHOICE=13 "$approve" "" n 2>/dev/null || true
assert_logged '^ward session approve --session sess_a 13 deny$'

# --- nothing pending -------------------------------------------------------------
: >"$MOCK_LOG"
mock ward 'case "$*" in "session pending --json "*) : ;; *) exit 1 ;; esac'
out=$("$approve")
assert_eq "$out" "  no pending approvals"
assert_not_logged '^ward session approve'

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"
