#!/usr/bin/env bash
# wardos-share: a file served from its directory with python's http.server, URL and QR shown.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock python3
mock qrencode
mock hostname 'echo "192.168.1.10 fd00::1"'
echo hello >"$TMP/report.pdf"

wardos-share --help | grep -q '^Usage' || fail "--help prints the usage block"

out=$(wardos-share --port 8080 "$TMP/report.pdf")
assert_logged "^python3 -m http.server 8080 --bind 0.0.0.0 --directory $TMP$"
grep -q 'http://192.168.1.10:8080/report.pdf' <<<"$out" || fail "the URL is printed; got: $out"
assert_logged '^qrencode -t ANSIUTF8 http://192.168.1.10:8080/report.pdf$'
# Without qrencode the URL alone is fine. (Captured whole: a pipe into `grep -q` closes
# early and the script's own writes would fail with a broken pipe.)
rm "$MOCK_DIR/qrencode"
out=$(wardos-share --port 8080 "$TMP/report.pdf")
grep -q 'http://' <<<"$out" || fail "URL without a QR; got: $out"
wardos-share "$TMP/missing" 2>/dev/null && fail "a missing file fails"
wardos-share 2>/dev/null && fail "a file is required"
exit 0
