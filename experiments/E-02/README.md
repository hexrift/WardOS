# E-02 — Snapshot performance

Spike for hypothesis 2 in `docs/experiments.md`: can entry/candidate capture of a
200k-file, 1 GB worktree be made fast enough that users never disable it?

The harness is `crates/ward-snapshot/examples/e02_snapshot_perf.rs`; it uses the real
`ward-snapshot` crate (no benchmark-specific code path). Results: [`RESULT.md`](RESULT.md).

```sh
./experiments/E-02/run.sh                    # 200k files, 1 GiB, in $TMPDIR/ward-e02
./experiments/E-02/run.sh --files 20000 --bytes 100M --runs 3   # quick variant
```

Generated data lives outside the repository; raw machine output goes to
`results/*.raw` (git-ignored). Only `RESULT.md` and the code are committed.
