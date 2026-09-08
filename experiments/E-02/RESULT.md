# E-02 Snapshot performance — result

Status: **partial pass, frozen-copy path only**. The Btrfs path (the one the hypothesis is
mainly about) could not be measured on this machine; the ext4 frozen-copy fallback meets
the warm criterion, misses the cold criterion by 0.5 s on hashing alone, and shows that
copying into the CAS while frozen is disk-bound and must not be on the frozen path.

Harness: `crates/ward-snapshot/examples/e02_snapshot_perf.rs` (runs the real crate; no
benchmark-only code path). Raw output: `results/run-20260908T003736Z.raw` (not committed).

## 1. Reproducibility record

```yaml
date: 2026-09-08
crate: ward-snapshot 0.1.0 @ phase-1/ward-snapshot (rustc 1.94.1, release profile)
kernel: 6.18.44-fc-v24 (Firecracker microVM)
cpu: Intel Xeon @ 2.80 GHz, 4 vCPUs
ram: 16 GiB (15.7 GiB MemTotal)
filesystem: ext4 on /dev/vda (virtio block, reports rotational=1, no model string)
disk_baseline: dd 512 MiB sequential + fsync = 254 MB/s
btrfs: NOT AVAILABLE (no Btrfs volume, no privilege to create a loop-mounted one)
cgroup: v1 hybrid hierarchy; cgroup.freeze not exercised (NoopFreezer used)
tree: 200,000 files, 1,073,715,967 bytes (1024.0 MiB), 61,823 directories,
      depth 2–5, fan-out 12; size mix 55 % <4 KiB, 35 % 4–64 KiB, 9 % 64 KiB–1 MiB,
      1 % 1–8 MiB; unique content per file; plus .gitignore and a small .git/
runs: cold = 1 run after `drop_caches=3`; warm = median of 5
```

This is a shared VM, not the reference desktop named in `docs/performance.md` §4. Numbers
are indicative of the *shape* of the costs, not of the reference hardware.

## 2. Measurements

| Metric | Value | Notes |
| --- | --- | --- |
| Entries in manifest | 261,827 (200,004 files) | includes `.git/`, `.gitignore` |
| **Cold full capture** (walk + hash + sort) | **3.47 s** | walk 0.71 s, hash 2.63 s → 390 MiB/s, I/O-bound |
| **Warm full capture** | **1.46 s** (median of 5) | walk 0.60 s, hash 0.66 s → 1,558 MiB/s on 4 vCPUs |
| Snapshot id stable across 5 warm runs | yes | |
| Cache build (warm, writes 200k records) | 1.42 s | |
| Cache save / load | 0.47 s / 0.10 s | 17.0 MiB postcard file |
| Cached capture, nothing changed | 0.83 s | 200,004 hits, 0 bytes read |
| **Cached incremental after touching 100 files** | **0.96 s** | 100 misses, 1.2 MiB hashed; walk is 0.61 s of it |
| CAS ingest, reflink attempted + fsync per blob | 61.8 s | 0 reflinks (ext4 → fell back to copy) |
| CAS ingest, plain copy + fsync per blob | 75.0 s | |
| CAS ingest, plain copy, deferred `syncfs` | **40.6 s** (39.9 copy + 0.76 syncfs) | 200k `create`+`rename` on ext4 |
| CAS disk usage | 1,641 MiB allocated for 1,024 MiB logical | 4 KiB block rounding on 200k small files |
| Materialise 200k files from CAS | 19.3 s | plain copies (no reflink on ext4) |
| Re-capture of materialised tree | 1.67 s, **id identical** | end-to-end roundtrip verified |

Small-scale calibration (3,000 files / 30 MiB, page cache hot) for the ingest modes:
fsync-per-blob 0.86–1.03 s, deferred 0.06 s copy + 0.17 s syncfs — a 4–5× difference
that shrinks to 1.5–1.9× at 1 GiB because the copy itself becomes write-bandwidth bound.

## 3. Against the E-02 pass criteria

| Criterion (`docs/experiments.md`) | Result | Verdict |
| --- | --- | --- |
| Btrfs: agent stall < 100 ms | not measurable here | **not measured** |
| Btrfs: hashing completes < 2 s warm | frozen-copy warm capture 1.46 s on 4 vCPUs (the same hashing would run off the ro snapshot) | pass, by proxy |
| ext4 frozen-copy stall < 3 s | warm 1.46 s **pass**; cold 3.47 s **fail** (hashing alone); cold+copy-into-CAS ≥ 44 s **fail** | **mixed** |
| ST-008/018 (TOCTOU) | not part of this spike; freezer contract and tests exist, no hostile workload run | not measured |

## 4. Findings

1. **Hashing is not the problem; I/O is.** Warm BLAKE3 over 1 GiB takes 0.66 s on 4 vCPUs
   (1.5 GiB/s). Cold, the same read runs at the disk's small-file read rate (390 MiB/s
   here). The walk (stat of 262k entries, `.gitignore` matching) is a fixed 0.6–0.7 s
   after parallelising it across cores (the sequential walker was 2.4× slower at small
   scale). On the reference NVMe desktop with 8+ cores, both halves should roughly halve.
2. **Copying into the CAS while frozen is not viable on ext4.** `docs/snapshots-and-git.md`
   §4 step 2 ("hash and copy from the frozen tree into the CAS, then thaw") costs 40–75 s
   for 1 GiB of small files on this disk, and even at 254 MB/s sequential it would be
   > 4 s. Per-blob `fsync` roughly doubles it. The stall budget can only be met if the
   *copy* is off the frozen path.
3. **The tree cache works but is bounded by the walk.** With the cache, a 100-file change
   costs 0.96 s of which 0.61 s is the stat walk, so the cache gives at most ~1.5× over
   warm and ~3.6× over cold on this tree. Its value is highest for cold captures on big
   files, which is not this workload.
4. **Reflink could not be exercised.** `FICLONE` is refused by ext4, so ingest and
   materialise both fell back to copies; the `reflink-copy` fallback path is what was
   measured. On Btrfs/XFS-reflink both would be metadata-only operations.
5. **Correctness held at scale**: 5 warm captures produced one id; store → materialise →
   re-capture reproduced it; 261,827-entry manifests parse strictly and sort bytewise.

## 5. What this means for the design

* **Btrfs for `/work` stays strongly recommended**, exactly as ADR-0010 says: it removes
  the copy from the frozen path (O(1) subvolume snapshot) and makes ingest a reflink.
  The claim "< 100 ms stall" still needs a Btrfs measurement; nothing here contradicts it.
* **Frozen-copy path, revised procedure (recommendation for `wardd`):** freeze → walk +
  hash (this is the stall: 1.5 s warm / 3.5 s cold here) → thaw → ingest with
  `IngestOptions { fsync_each: false }` from the *live* tree with `verify: true` → `Store::sync()`.
  Because the manifest hashes are authoritative, any file the agent changes between thaw
  and ingest is detected as a `HashMismatch`; `wardd` then re-freezes and retries just
  those files (or falls back to the full-frozen copy). This keeps durability (one
  `syncfs`) without paying 200k `fsync`s inside the stall.
* **Use the tree cache for candidate captures only** (see `src/cache.rs` for the trust
  rules); it never makes an accepted snapshot cheaper to fake, because accepted ids are
  computed from a full hash.
* **Fallback path if Btrfs is unavailable in the portable runtime**: the loop-mounted
  Btrfs image from `docs/experiments.md` E-02 "if fail" is the right answer; incremental-
  only hashing cannot close the gap because the walk alone is 0.6 s per 260k entries.

## 6. Not measured here (must be run on the reference desktop)

* Btrfs subvolume snapshot stall and reflink ingest/materialise.
* Real `cgroup.freeze` latency (`CgroupV2Freezer` waits for `frozen 1` in
  `cgroup.events`; the wait loop is tested against a fake cgroup directory only).
* ST-008/ST-018 hostile-writer TOCTOU tests.
* NVMe cold-read behaviour and > 4 core scaling of the parallel walk and hash.

## 7. How to reproduce

```sh
./experiments/E-02/run.sh                                  # defaults: 200k files, 1 GiB
./experiments/E-02/run.sh --files 20000 --bytes 100M --runs 3 --touch 50
```

The harness drops the page cache via `/proc/sys/vm/drop_caches` when permitted and
otherwise evicts the tree with `syncfs` + `posix_fadvise(DONTNEED)` per file, and prints
which of the two happened (`page_cache_eviction`).
