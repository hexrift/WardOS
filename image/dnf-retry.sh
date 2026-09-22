#!/usr/bin/env bash
# Shared by image/check-packages.sh and image/check-hyprland.sh (issue #198): a bounded
# retry with backoff for the `dnf copr enable`/`dnf install` calls those scripts and the
# Containerfile make against upstream Fedora/COPR mirrors, and a classifier that reads
# dnf's own output to tell a transient mirror/network hiccup apart from a package that
# genuinely does not exist, so a red check reads as one or the other instead of requiring
# someone to re-derive it from the raw dnf log every time (as #193/#195/#197 each did).
#
# Sourced on the host by check-packages.sh/check-hyprland.sh for classify_dnf_failure,
# and reproduced verbatim (the `retry` function only) inside the ephemeral Fedora
# container each script runs dnf in, and in the Containerfile's own COPR-enable step --
# none of those can source a host file without a bind mount for what is a few lines of
# bash. Keep every copy of `retry` identical to this one; image/dnf-retry.test.sh is what
# proves this one behaves, and image-lint's shellcheck/bash -n pass covers this file
# itself the same as every other image/*.sh.

# retry MAX DELAY CMD...: run CMD, retrying up to MAX total attempts, sleeping DELAY
# seconds before the first retry and doubling that delay each attempt after. Returns
# CMD's own exit status, whether it eventually succeeded or the budget ran out.
retry() {
  local max=$1 delay=$2 n=1 rc=0
  shift 2
  until "$@"; do
    rc=$?
    if ((n >= max)); then return "$rc"; fi
    echo "retry: attempt $n/$max failed (exit $rc), retrying in ${delay}s: $*" >&2
    sleep "$delay"
    delay=$((delay * 2))
    n=$((n + 1))
  done
}

# classify_dnf_failure FILE: prints "transient" when FILE (captured dnf/copr stderr)
# reads like an upstream mirror/network/COPR-availability problem, else "genuine" (a
# real missing/renamed package, or any other dnf error). Pattern-matched against known
# transient wording, not exhaustive; a miss falls back to "genuine" -- the safe default,
# since it never quietly waves off a real failure as someone else's outage.
#
# Callers should classify last_step_tail's output, not a whole multi-step log: an
# earlier step's transient hiccup that then recovered on its own retry must not paint a
# later, unrelated, genuinely-failing step as an outage (or vice versa).
classify_dnf_failure() {
  local file=$1
  if grep -qEi \
    'Failed to synchronize cache|Cannot prepare internal mirrorlist|No more mirrors to try|Could not resolve host|Temporary failure in name resolution|Connection timed out|Connection reset by peer|Errno 14|TLS handshake|SSL error|Network is unreachable' \
    "$file" 2>/dev/null; then
    echo transient
  else
    echo genuine
  fi
}

# The marker each container-side copy of retry's caller prints to its own stderr
# immediately before a distinct step starts (the dnf5-plugins install, each COPR
# enable, the final install/repoquery, or a step that isn't retried at all, like
# Hyprland's own --verify-config in check-hyprland.sh): whatever a container's combined
# log says before the LAST marker belongs to a step that, by the time the container
# exited, had already either succeeded or not yet been reached -- only the text after
# it can belong to the step that was actually running when the container exited.
DNF_RETRY_STEP_MARK='##dnf-retry:step##'

# last_step_tail FILE: prints FILE's content from after the last DNF_RETRY_STEP_MARK
# line, or the whole file when no marker appears (a failure before the first marked
# step, or a caller that never marks one) -- never a narrower view than classifying the
# whole file in that case, only ever narrower once a step boundary is known.
last_step_tail() {
  local file=$1 line
  # `|| true`: under the callers' `set -e`, grep finding no marker makes this whole
  # pipeline (pipefail) exit non-zero, and a plain assignment statement is NOT exempt
  # from errexit just because it's a command substitution -- without this, a log with
  # no marker would abort the caller's script right here instead of reaching the
  # documented "no marker -> return the whole file" fallback below. `line` still ends
  # up empty in that case; `|| true` only neutralises the exit status, not the capture.
  line=$(grep -nF "$DNF_RETRY_STEP_MARK" "$file" 2>/dev/null | tail -n 1 | cut -d: -f1) || true
  if [[ -n "$line" ]]; then
    tail -n "+$((line + 1))" "$file"
  else
    cat "$file" 2>/dev/null
  fi
}
