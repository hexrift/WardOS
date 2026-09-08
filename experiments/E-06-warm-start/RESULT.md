# E-06 — Sandbox warm start

Status: **CANNOT-MEASURE-HERE**

## Hypothesis

With pre-pulled layers and a prepared spec, `ward claude` reaches agent PID 1 exec in < 150 ms; a frozen-and-thawed persistent sandbox resumes in < 30 ms (docs/experiments.md E-06).

## Method

Build a minimal rootless OCI bundle (`/bin/true` as the rootfs payload, user/mount/pid/ipc/uts namespaces, empty capabilities, `noNewPrivileges`, no cgroup limits) and time `crun run` — create + start + wait-for-exit — over 50 iterations, reporting p50/p99 wall-clock. This isolates the OCI-runtime floor of architecture §4 steps 5 and 9; the full warm path additionally includes policy load, snapshot, netns and inner hardening, measured separately once those crates land.

## Result

**CANNOT-MEASURE-HERE.** cgroups in hybrid mode not supported, drop all controllers from cgroupv2

This environment is a sandbox-in-sandbox with hybrid (v1+v2) cgroups, in which `crun` refuses to create a container (`cgroups in hybrid mode not supported`). Spec generation and schema acceptance are still validated by the `ward-sandbox` crate tests; only the runtime timing cannot be gathered here.

### Run this on a real unprivileged Linux host (cgroups v2 unified)

```sh
# host prerequisites: crun installed, unprivileged userns enabled,
# a cgroups v2 'unified' hierarchy (stat -fc %T /sys/fs/cgroup == cgroup2fs)
cd experiments/E-06-warm-start
cargo run --release
# prints p50/p99 and rewrites RESULT.md with the measured table
```


## Pass criterion

< 150 ms fresh, < 30 ms freezer-resume on reference hardware. The freezer-resume path is not exercised by this spike (it needs a persistent frozen sandbox from `wardd`) and is deferred.
