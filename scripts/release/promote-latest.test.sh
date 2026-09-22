#!/usr/bin/env bash
# Regressions for promote-latest.sh (issue #149): `latest` is written by
# exactly one call, targeting exactly the digest this run captured, only
# when this run's commit is still main's tip. Covers three of #149's
# distinct acceptance cases: a superseded run never invokes docker at all
# (overlapping runs finishing out of order); a run interrupted strictly
# before the write leaves `latest` untouched (cancellation before
# promotion, exercised via a deterministic ready/go rendezvous, not a sleep
# race); and a retry re-promotes whatever digest it is given, faithfully.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/promote-latest.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

log="$work/docker-calls.log"
fake_docker="$work/fake-docker"
cat >"$fake_docker" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$DOCKER_CALL_LOG"
EOF
chmod +x "$fake_docker"

run_with_fake_docker() {
  rm -f "$log"
  DOCKER="$fake_docker" DOCKER_CALL_LOG="$log" bash "$sut" "$@"
}

# Still the tip: promotes by digest, in exactly two docker calls (create,
# then the inspect that proves it landed), and no other digest or tag.
run_with_fake_docker ghcr.io/example/wardos sha256:deadbeef abc123 abc123
[[ -f "$log" ]] || fail "still-the-tip: docker was never invoked"
calls=$(wc -l <"$log")
[[ "$calls" == 2 ]] || fail "still-the-tip: expected 2 docker calls (create, inspect), got $calls"
grep -qF 'buildx imagetools create -t ghcr.io/example/wardos:latest ghcr.io/example/wardos@sha256:deadbeef' "$log" \
  || fail "still-the-tip: create call did not target the captured digest"
echo "ok   still the tip promotes exactly the captured digest"

# Superseded by a newer commit (overlapping runs finishing out of order):
# docker is never invoked at all, so `latest` cannot have been touched --
# this is also what makes cancellation before this point moot, made
# concrete rather than asserted in a comment.
rm -f "$log"
DOCKER="$fake_docker" DOCKER_CALL_LOG="$log" bash "$sut" ghcr.io/example/wardos sha256:deadbeef abc123 def456
[[ ! -s "$log" ]] || fail "superseded: docker was invoked but should not have been"
echo "ok   superseded commit never calls docker"

# A retry of a still-current commit (nothing else landed meanwhile) issues
# the identical, deterministic call again -- idempotent because it is the
# same digest and the same command, not because any tag is assumed to be
# unwritable.
run_with_fake_docker ghcr.io/example/wardos sha256:deadbeef abc123 abc123
calls=$(wc -l <"$log")
[[ "$calls" == 2 ]] || fail "retry: expected 2 docker calls, got $calls"
echo "ok   retry of the still-current tip re-promotes the same digest"

# Cancellation strictly before the shared-tag write: a genuinely different
# state from the superseded case above, which never even reaches the write
# path. This one does, and is interrupted while blocked immediately before
# the one command that can touch `latest` -- and must leave `latest`
# untouched. The rendezvous is a file's existence, not a sleep duration, so
# there is no timing race in what the assertion depends on.
barrier="$work/barrier"
mkdir -p "$barrier"
mkfifo "$barrier/go"
rm -f "$log"
PROMOTE_LATEST_BARRIER_DIR="$barrier" DOCKER="$fake_docker" DOCKER_CALL_LOG="$log" \
  bash "$sut" ghcr.io/example/wardos sha256:deadbeef abc123 abc123 &
pid=$!

deadline=$((SECONDS + 5))
until [[ -e "$barrier/ready" ]]; do
  if ((SECONDS >= deadline)); then
    kill "$pid" 2>/dev/null || true
    fail "cancellation: promote-latest.sh never reached the pre-write barrier"
  fi
  sleep 0.05
done

kill -TERM "$pid"
wait "$pid" 2>/dev/null || true
[[ ! -s "$log" ]] || fail "cancellation: docker was invoked despite being killed before the write"
echo "ok   cancellation strictly before the write never touches latest"

# The script never assumes two runs of the same commit produced the same
# bytes: it has no cache and no memory of a previous invocation, so a
# second run that was handed a genuinely different (re-)built digest
# promotes THAT digest faithfully, not a stale one left over from the
# first call above.
run_with_fake_docker ghcr.io/example/wardos sha256:c0ffee abc123 abc123
grep -qF 'buildx imagetools create -t ghcr.io/example/wardos:latest ghcr.io/example/wardos@sha256:c0ffee' "$log" \
  || fail "rebuilt retry: did not promote the newly given digest"
grep -qF 'sha256:deadbeef' "$log" \
  && fail "rebuilt retry: promoted a stale digest from an earlier invocation"
echo "ok   a differently-rebuilt retry promotes its own digest, not a cached one"

# Missing arguments are rejected rather than silently promoting garbage.
expect_status 1 "missing digest rejected" bash "$sut" ghcr.io/example/wardos
expect_status 1 "missing tip sha rejected" bash "$sut" ghcr.io/example/wardos sha256:deadbeef abc123

echo "PASS promote-latest.test.sh"
