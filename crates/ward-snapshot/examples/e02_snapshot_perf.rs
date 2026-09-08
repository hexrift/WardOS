//! E-02 snapshot performance harness (`docs/experiments.md`, E-02).
//!
//! Generates a synthetic worktree (default 200k files, ~1 GiB, realistic depth and size
//! mix), then measures the frozen-copy path of `ward-snapshot`:
//!
//! 1. cold full hash (page cache dropped when permitted),
//! 2. warm full hash (median of N runs),
//! 3. cache build, then cached incremental hash after touching 100 files,
//! 4. CAS ingest with and without reflink, with disk usage,
//! 5. materialise from the CAS and re-capture to confirm the id.
//!
//! Usage: `cargo run --release --example e02_snapshot_perf -- [--dir D] [--files N]
//! [--bytes B] [--touch T] [--runs R] [--out results.raw] [--keep] [--reuse]`.
//!
//! The Btrfs subvolume path is *not* exercised here: it needs a Btrfs `/work`, which
//! this harness cannot create without privileges. The numbers it reports are the
//! frozen-copy fallback only.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ward_snapshot::{
    CapturePolicy, CaptureStats, IngestOptions, NoopFreezer, Store, TreeCache,
    capture_with_freezer, materialise,
};

type BoxError = Box<dyn std::error::Error>;

struct Args {
    dir: PathBuf,
    files: u64,
    bytes: u64,
    touch: usize,
    runs: usize,
    out: Option<PathBuf>,
    keep: bool,
    reuse: bool,
}

fn parse_size(s: &str) -> Result<u64, BoxError> {
    let (num, mult) = match s.chars().last() {
        Some('G' | 'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some('M' | 'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        _ => (s, 1),
    };
    Ok(num.parse::<u64>()? * mult)
}

fn parse_args() -> Result<Args, BoxError> {
    let mut args = Args {
        dir: std::env::temp_dir().join("ward-e02"),
        files: 200_000,
        bytes: 1 << 30,
        touch: 100,
        runs: 5,
        out: None,
        keep: false,
        reuse: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--dir" => args.dir = PathBuf::from(value()?),
            "--files" => args.files = value()?.parse()?,
            "--bytes" => args.bytes = parse_size(&value()?)?,
            "--touch" => args.touch = value()?.parse()?,
            "--runs" => args.runs = value()?.parse()?,
            "--out" => args.out = Some(PathBuf::from(value()?)),
            "--keep" => args.keep = true,
            "--reuse" => args.reuse = true,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    Ok(args)
}

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Size mix modelled on a large monorepo: mostly small sources, a tail of assets.
fn pick_size(rng: &mut Rng) -> u64 {
    match rng.below(1000) {
        0..=549 => rng.below(4 * 1024),                 // 55 %: < 4 KiB
        550..=899 => 4 * 1024 + rng.below(60 * 1024),   // 35 %: 4–64 KiB
        900..=989 => 64 * 1024 + rng.below(960 * 1024), // 9 %: 64 KiB–1 MiB
        _ => 1024 * 1024 + rng.below(7 * 1024 * 1024),  // 1 %: 1–8 MiB
    }
}

fn generate(root: &Path, files: u64, target_bytes: u64) -> Result<(u64, Duration), BoxError> {
    let t0 = Instant::now();
    if root.exists() {
        fs::remove_dir_all(root)?;
    }
    fs::create_dir_all(root)?;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut sizes: Vec<u64> = (0..files).map(|_| pick_size(&mut rng)).collect();
    let sum: u64 = sizes.iter().sum();
    let scale = target_bytes as f64 / sum.max(1) as f64;
    for s in &mut sizes {
        *s = (*s as f64 * scale) as u64;
    }
    // A 4 MiB random block; each file gets a unique 16-byte header plus a slice of it
    // (unique content, so the CAS cannot dedupe and the hasher sees real bytes).
    let block: Vec<u8> = (0..4 * 1024 * 1024).map(|_| rng.next() as u8).collect();
    let dirs_per_level = 12u64;
    let mut total = 0u64;
    let mut buf = Vec::with_capacity(8 * 1024 * 1024);
    for (i, size) in sizes.iter().enumerate() {
        let i = i as u64;
        // Depth 2–5, fan-out 12: ~200k files spread over ~20k directories.
        let depth = 2 + (i % 4);
        let mut dir = root.to_path_buf();
        let mut key = i;
        for level in 0..depth {
            dir.push(format!("d{level}_{}", key % dirs_per_level));
            key /= dirs_per_level;
        }
        fs::create_dir_all(&dir)?;
        let ext = ["rs", "ts", "go", "py", "json", "md", "png", "lock"][(i % 8) as usize];
        let path = dir.join(format!("f{i}.{ext}"));
        buf.clear();
        buf.extend_from_slice(&i.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        let mut remaining = size.saturating_sub(16) as usize;
        let mut off = (i as usize * 4099) % block.len();
        while remaining > 0 {
            let n = remaining.min(block.len() - off);
            buf.extend_from_slice(&block[off..off + n]);
            remaining -= n;
            off = 0;
        }
        fs::write(&path, &buf)?;
        total += buf.len() as u64;
    }
    fs::write(root.join(".gitignore"), "target/\n*.tmp\n")?;
    fs::create_dir_all(root.join(".git/refs/heads"))?;
    fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n")?;
    fs::write(
        root.join(".git/refs/heads/main"),
        "0123456789abcdef0123456789abcdef01234567\n",
    )?;
    fs::write(
        root.join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n",
    )?;
    Ok((total, t0.elapsed()))
}

/// Try the global `drop_caches` knob first (root, and not in a sandbox); otherwise
/// evict just this tree's pages with `syncfs` + `posix_fadvise(DONTNEED)` per file, which
/// needs no privilege. Returns a description of what happened.
fn evict_page_cache(root: &Path) -> String {
    let global = fs::OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
        .and_then(|mut f| f.write_all(b"3"))
        .is_ok();
    if global {
        return "global drop_caches=3".to_owned();
    }
    let Ok(dir) = fs::File::open(root) else {
        return "none (cannot open root)".to_owned();
    };
    if let Err(e) = rustix::fs::syncfs(&dir) {
        return format!("none (syncfs failed: {e})");
    }
    let mut evicted = 0u64;
    let mut failed = 0u64;
    for e in walkdir::WalkDir::new(root).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let ok = fs::File::open(e.path()).ok().is_some_and(|f| {
            rustix::fs::fadvise(&f, 0, None, rustix::fs::Advice::DontNeed).is_ok()
        });
        if ok {
            evicted += 1;
        } else {
            failed += 1;
        }
    }
    format!("per-file fadvise(DONTNEED): evicted {evicted}, failed {failed}")
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn hash_once(root: &Path, cache: Option<&mut TreeCache>) -> Result<CaptureStats, BoxError> {
    let (_, stats) = capture_with_freezer(root, &CapturePolicy::default(), cache, &NoopFreezer)?;
    Ok(stats)
}

fn mount_info(path: &Path) -> (String, String) {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mut best: Option<(usize, String, String)> = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let mp = Path::new(f[1]);
        if canonical.starts_with(mp) && best.as_ref().is_none_or(|b| f[1].len() > b.0) {
            best = Some((f[1].len(), f[0].to_owned(), f[2].to_owned()));
        }
    }
    best.map_or(("?".into(), "?".into()), |(_, dev, fstype)| (dev, fstype))
}

fn disk_model(dev: &str) -> String {
    let name = dev.trim_start_matches("/dev/");
    let base: String = name
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .to_owned();
    for candidate in [&base, &name.to_owned()] {
        let sys = Path::new("/sys/block").join(candidate);
        let model = fs::read_to_string(sys.join("device/model")).unwrap_or_default();
        let rota = fs::read_to_string(sys.join("queue/rotational")).unwrap_or_default();
        if !model.is_empty() || !rota.is_empty() {
            return format!(
                "{} (model: {}; rotational: {})",
                candidate,
                if model.trim().is_empty() {
                    "n/a"
                } else {
                    model.trim()
                },
                rota.trim()
            );
        }
    }
    format!("{name} (no /sys/block entry)")
}

fn dir_size(path: &Path) -> (u64, u64) {
    let mut allocated = 0;
    let mut logical = 0;
    for e in walkdir::WalkDir::new(path).into_iter().flatten() {
        if let Ok(m) = e.metadata()
            && m.is_file()
        {
            allocated += m.blocks() * 512;
            logical += m.len();
        }
    }
    (allocated, logical)
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

fn mib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

struct Results {
    values: BTreeMap<&'static str, String>,
}

impl Results {
    fn put(&mut self, k: &'static str, v: impl std::fmt::Display) {
        println!("  {k:<44} {v}");
        self.values.insert(k, v.to_string());
    }
}

fn environment(args: &Args, r: &mut Results) {
    let (dev, fstype) = mount_info(&args.dir);
    r.put(
        "cpus",
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
    );
    r.put(
        "kernel",
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim(),
    );
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            l.strip_prefix("model name")
                .map(|s| s.trim_start_matches([' ', ':', '\t']).to_owned())
        })
        .unwrap_or_default();
    r.put("cpu_model", cpu);
    let mem = fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:").map(|s| s.trim().to_owned()))
        .unwrap_or_default();
    r.put("mem_total", mem);
    r.put("filesystem", format!("{fstype} on {dev}"));
    r.put("disk", disk_model(&dev));
    r.put("dir", args.dir.display());
    r.put(
        "btrfs_path",
        "NOT MEASURED (no Btrfs available on this host)",
    );
}

fn phase_generate(args: &Args, work: &Path, r: &mut Results) -> Result<(), BoxError> {
    println!("== generate");
    if args.reuse && work.is_dir() {
        r.put("generate", "reused existing tree");
    } else {
        let (bytes, d) = generate(work, args.files, args.bytes)?;
        r.put("generate_files", args.files);
        r.put(
            "generate_bytes",
            format!("{} ({:.1} MiB)", bytes, mib(bytes)),
        );
        r.put("generate_secs", format!("{:.2}", secs(d)));
    }
    Ok(())
}

fn phase_cold(work: &Path, r: &mut Results) -> Result<u64, BoxError> {
    println!("== cold full hash");
    r.put("page_cache_eviction", evict_page_cache(work));
    let s = hash_once(work, None)?;
    r.put("entries", s.entries);
    r.put("files", s.files);
    r.put(
        "bytes_hashed",
        format!("{} ({:.1} MiB)", s.bytes_hashed, mib(s.bytes_hashed)),
    );
    r.put("cold_walk_secs", format!("{:.3}", secs(s.walk_duration)));
    r.put("cold_hash_secs", format!("{:.3}", secs(s.hash_duration)));
    r.put(
        "cold_total_secs (agent-visible stall, frozen-copy)",
        format!("{:.3}", secs(s.frozen_for.unwrap_or_default())),
    );
    r.put(
        "cold_throughput_MiB_per_s",
        format!(
            "{:.0}",
            mib(s.bytes_hashed) / secs(s.hash_duration).max(1e-9)
        ),
    );
    Ok(s.bytes_hashed)
}

fn phase_warm(args: &Args, work: &Path, bytes: u64, r: &mut Results) -> Result<(), BoxError> {
    println!("== warm full hash (median of {} runs)", args.runs);
    let mut walks = Vec::new();
    let mut hashes = Vec::new();
    let mut totals = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..args.runs.max(1) {
        let (m, s) = capture_with_freezer(work, &CapturePolicy::default(), None, &NoopFreezer)?;
        ids.push(m.id());
        walks.push(secs(s.walk_duration));
        hashes.push(secs(s.hash_duration));
        totals.push(secs(s.frozen_for.unwrap_or_default()));
    }
    let stable = ids.windows(2).all(|w| w[0] == w[1]);
    r.put("warm_ids_identical", stable);
    r.put(
        "warm_walk_secs_median",
        format!("{:.3}", median(&mut walks)),
    );
    r.put(
        "warm_hash_secs_median",
        format!("{:.3}", median(&mut hashes)),
    );
    r.put(
        "warm_total_secs_median",
        format!("{:.3}", median(&mut totals)),
    );
    r.put(
        "warm_throughput_MiB_per_s",
        format!("{:.0}", mib(bytes) / median(&mut hashes).max(1e-9)),
    );
    Ok(())
}

fn phase_cache(args: &Args, work: &Path, r: &mut Results) -> Result<(), BoxError> {
    println!("== tree cache");
    let mut cache = TreeCache::new();
    let s = hash_once(work, Some(&mut cache))?;
    r.put(
        "cache_build_secs",
        format!("{:.3}", secs(s.frozen_for.unwrap_or_default())),
    );
    let cache_file = args.dir.join("tree-cache.bin");
    let t = Instant::now();
    cache.save(&cache_file)?;
    r.put("cache_save_secs", format!("{:.3}", secs(t.elapsed())));
    let t = Instant::now();
    let mut cache = TreeCache::load(&cache_file)?;
    r.put("cache_load_secs", format!("{:.3}", secs(t.elapsed())));
    r.put("cache_file_bytes", fs::metadata(&cache_file)?.len());
    let s = hash_once(work, Some(&mut cache))?;
    r.put(
        "cached_nochange_secs",
        format!("{:.3}", secs(s.frozen_for.unwrap_or_default())),
    );
    r.put("cached_nochange_hits", s.cache_hits);

    // Touch: rewrite `touch` files with different content of the same size.
    let mut touched = 0usize;
    for e in walkdir::WalkDir::new(work).into_iter().flatten() {
        if touched >= args.touch {
            break;
        }
        if e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs") {
            let mut content = fs::read(e.path())?;
            if let Some(b) = content.first_mut() {
                *b = b.wrapping_add(1);
            }
            fs::write(e.path(), &content)?;
            touched += 1;
        }
    }
    let s = hash_once(work, Some(&mut cache))?;
    r.put("touched_files", touched);
    r.put(
        "cached_incremental_secs",
        format!("{:.3}", secs(s.frozen_for.unwrap_or_default())),
    );
    r.put(
        "cached_incremental_walk_secs",
        format!("{:.3}", secs(s.walk_duration)),
    );
    r.put("cached_incremental_hits", s.cache_hits);
    r.put("cached_incremental_misses", s.cache_misses);
    r.put("cached_incremental_bytes_hashed", s.bytes_hashed);
    Ok(())
}

fn phase_materialise(
    args: &Args,
    store: &Store,
    manifest: &ward_snapshot::Manifest,
    r: &mut Results,
) -> Result<(), BoxError> {
    println!("== materialise");
    let dest = args.dir.join("materialised");
    if dest.exists() {
        fs::remove_dir_all(&dest)?;
    }
    let t = Instant::now();
    let mrep = materialise(store, &manifest.id(), &dest)?;
    r.put("materialise_secs", format!("{:.3}", secs(t.elapsed())));
    r.put(
        "materialise_files",
        format!("{} (reflinked {})", mrep.files, mrep.reflinked),
    );
    let (alloc, _) = dir_size(&dest);
    r.put("materialise_disk_MiB", format!("{:.1}", mib(alloc)));
    let (again, s2) = capture_with_freezer(&dest, &CapturePolicy::default(), None, &NoopFreezer)?;
    r.put("materialised_id_matches", again.id() == manifest.id());
    r.put(
        "materialised_rehash_secs",
        format!("{:.3}", secs(s2.frozen_for.unwrap_or_default())),
    );
    fs::remove_dir_all(&dest)?;
    Ok(())
}

fn phase_ingest(args: &Args, work: &Path, r: &mut Results) -> Result<(), BoxError> {
    println!("== CAS ingest");
    let (manifest, _) = capture_with_freezer(work, &CapturePolicy::default(), None, &NoopFreezer)?;
    let modes: [(&'static str, IngestOptions, [&'static str; 3]); 3] = [
        (
            "reflink+fsync",
            IngestOptions {
                use_reflink: true,
                verify: false,
                fsync_each: true,
            },
            [
                "ingest_reflink_fsync_secs",
                "ingest_reflink_fsync_blobs",
                "ingest_reflink_fsync_disk_MiB",
            ],
        ),
        (
            "copy+fsync",
            IngestOptions {
                use_reflink: false,
                verify: false,
                fsync_each: true,
            },
            [
                "ingest_copy_fsync_secs",
                "ingest_copy_fsync_blobs",
                "ingest_copy_fsync_disk_MiB",
            ],
        ),
        (
            "copy+deferred-syncfs",
            IngestOptions {
                use_reflink: false,
                verify: false,
                fsync_each: false,
            },
            [
                "ingest_copy_deferred_secs",
                "ingest_copy_deferred_blobs",
                "ingest_copy_deferred_disk_MiB",
            ],
        ),
    ];
    for (label, opts, keys) in modes {
        let store_dir = args.dir.join("cas");
        if store_dir.exists() {
            fs::remove_dir_all(&store_dir)?;
        }
        let store = Store::open(&store_dir)?;
        let t = Instant::now();
        store.put_manifest(&manifest)?;
        let rep = store.ingest(work, &manifest, opts)?;
        let copy_secs = secs(t.elapsed());
        let sync_secs = if opts.fsync_each {
            0.0
        } else {
            let t = Instant::now();
            store.sync()?;
            secs(t.elapsed())
        };
        let (alloc, logical) = store.blob_disk_usage()?;
        println!("  [{label}]");
        r.put(
            keys[0],
            format!(
                "{:.3} (copy {:.3} + sync {:.3})",
                copy_secs + sync_secs,
                copy_secs,
                sync_secs
            ),
        );
        r.put(
            keys[1],
            format!(
                "written {} (reflinked {}, copied {}), existing {}",
                rep.blobs_written, rep.reflinked, rep.copied, rep.blobs_existing
            ),
        );
        r.put(
            keys[2],
            format!("allocated {:.1}, logical {:.1}", mib(alloc), mib(logical)),
        );
        if opts.use_reflink {
            phase_materialise(args, &store, &manifest, r)?;
        }
        fs::remove_dir_all(&store_dir)?;
    }
    r.put("snapshot_id", manifest.id());
    Ok(())
}

fn run(args: &Args) -> Result<Results, BoxError> {
    let mut r = Results {
        values: BTreeMap::new(),
    };
    println!("== environment");
    environment(args, &mut r);
    let work = args.dir.join("work");
    phase_generate(args, &work, &mut r)?;
    let bytes = phase_cold(&work, &mut r)?;
    phase_warm(args, &work, bytes, &mut r)?;
    phase_cache(args, &work, &mut r)?;
    phase_ingest(args, &work, &mut r)?;
    Ok(r)
}

fn main() -> Result<(), BoxError> {
    let args = parse_args()?;
    let results = run(&args);
    if !args.keep && args.dir.exists() {
        let _ = fs::remove_dir_all(&args.dir);
    }
    let results = results?;
    if let Some(out) = &args.out {
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::File::create(out)?;
        for (k, v) in &results.values {
            writeln!(f, "{k}\t{v}")?;
        }
        println!("raw results written to {}", out.display());
    }
    Ok(())
}
