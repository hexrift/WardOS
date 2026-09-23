//! `ward ready`: a structured preflight report of what a project needs before an
//! agent starts (#147) — so a missing prerequisite is visible up front, in one
//! command, instead of surfacing mid-run as a confusing `ward verify` failure.
//!
//! This is the project-scoped counterpart to [`crate::doctor`]'s host-scoped report:
//! where `ward doctor` asks "can this host run a session at all", `ward ready` asks
//! "does *this* project resolve to a runnable, protected verification" — reading
//! exactly what `ward init` writes (`.ward/policy.yaml`, `.tamperward/config.yml`)
//! and reporting whether it resolves, not merely whether the files exist.
//!
//! Scope: this covers items 1 and 5 of #147's suggested implementation (a structured
//! report; Ready / Ready with limitations / Setup required / Verification
//! unavailable). It does not run the guessed command to distinguish a legitimate
//! pre-existing failing test ("baseline failing") from a broken setup, and it does
//! not prepare or cache an isolated dependency environment (items 2–4, 6) — both are
//! substantial follow-ups of their own (the second needs the same disposable-sandbox
//! machinery `ward verify` already owns) and are left for later PRs against #147.

use std::path::{Path, PathBuf};

use crate::doctor::Status;
use crate::verify;

/// The build system a directory shows: decides the guessed verify command `ward
/// init` writes into `.tamperward/config.yml`. Only used for that guess and for the
/// report's header line — the `runtime` row below checks the *configured* command,
/// not this detection, so a project that overrides the guess is checked correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    /// `Cargo.toml` at the root.
    Cargo,
    /// `package.json` at the root.
    Npm,
    /// `pyproject.toml` at the root.
    Python,
    /// No recognised build manifest.
    Unknown,
}

impl Ecosystem {
    /// Detect from the build manifest a directory has at its root.
    #[must_use]
    pub fn detect(dir: &Path) -> Self {
        if dir.join("Cargo.toml").is_file() {
            Self::Cargo
        } else if dir.join("package.json").is_file() {
            Self::Npm
        } else if dir.join("pyproject.toml").is_file() {
            Self::Python
        } else {
            Self::Unknown
        }
    }

    /// The command `ward init` guesses for this ecosystem.
    #[must_use]
    pub const fn verify_command(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("cargo test"),
            Self::Npm => Some("npm test"),
            Self::Python => Some("pytest"),
            Self::Unknown => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Python => "python",
            Self::Unknown => "unrecognised",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One row of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Short name.
    pub name: &'static str,
    /// Outcome.
    pub status: Status,
    /// What was found and, on `Warn`/`Fail`, what to do.
    pub detail: String,
}

impl Row {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// The report's overall outcome (#147's suggested five states, minus "baseline
/// failing" — see the module doc for why that one needs a later PR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every row resolves; an agent can start and `ward verify` can run.
    Ready,
    /// Every row resolves well enough to proceed, with a documented degradation
    /// (e.g. nothing is listed under `protected.tests` yet).
    Limited,
    /// A row that blocks a session is unresolved (missing runtime, unparsable
    /// policy or verifier config).
    SetupRequired,
    /// No verify command is configured at all, so readiness cannot be judged past
    /// that point — distinct from `SetupRequired`, whose command exists but fails
    /// one of its own preconditions.
    Unavailable,
}

impl Verdict {
    /// The word `ward ready` prints for this outcome.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Limited => "ready, with limitations",
            Self::SetupRequired => "setup required",
            Self::Unavailable => "verification unavailable",
        }
    }

    /// Whether an agent should be allowed to start without an explicit override.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::SetupRequired | Self::Unavailable)
    }
}

/// The full preflight report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The detected build system, for the header line.
    pub ecosystem: Ecosystem,
    /// One row per check, in the order a user would fix them.
    pub rows: Vec<Row>,
    /// No verify command is configured; see [`Verdict::Unavailable`].
    unavailable: bool,
}

impl Report {
    /// Append a row a caller computed itself (the CLI adds the credential row,
    /// which needs to know which agent's key to look for — this crate does not).
    pub fn push(&mut self, row: Row) {
        self.rows.push(row);
    }

    /// The overall outcome across every row pushed so far.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if self.unavailable {
            Verdict::Unavailable
        } else if self.rows.iter().any(|r| r.status == Status::Fail) {
            Verdict::SetupRequired
        } else if self.rows.iter().any(|r| r.status == Status::Warn) {
            Verdict::Limited
        } else {
            Verdict::Ready
        }
    }
}

/// Run the project-scoped checks against `dir` (a `ward init`-style project root).
/// Does not touch the network and runs no project command — only reads the two
/// config files `ward init` writes and probes, for the `runtime` row, the same
/// directories `ward verify` itself would actually search inside the verifier
/// sandbox (see [`verify::Toolchains::search_dirs`]) — not the calling
/// process's own `PATH`, which the verifier does not use.
#[must_use]
pub fn check(dir: &Path) -> Report {
    let toolchains = verify::Toolchains::detect();
    check_with_dirs_and_roots(dir, &toolchains.search_dirs(), &toolchains.mounts())
}

/// [`check`], with the verifier's search directories given explicitly instead
/// of detected from the host — what `check` itself does, via a fixed list
/// rather than a live `Toolchains::detect()`, so a test can exercise the
/// `runtime` row's search with controlled directories instead of depending on
/// whatever Rust toolchain happens to be installed on the machine running the
/// test. No explicit [`verify::Mount`]s: every search dir here is judged as
/// its own boundary (see [`resolve_in_dirs`]'s doc for what that means) —
/// correct for every caller that doesn't need a search dir's real mount
/// picture to differ from the directory itself; a caller that does (a search
/// dir that is only one of several sibling directories actually mounted, as
/// `bin`/`registry` are under a real `$CARGO_HOME`) uses
/// [`check_with_dirs_and_roots`] directly.
#[cfg(test)]
fn check_with_dirs(dir: &Path, search_dirs: &[PathBuf]) -> Report {
    check_with_dirs_and_roots(dir, search_dirs, &[])
}

/// [`check`]'s real implementation: `search_dirs` is where a bare candidate is
/// looked up (mirroring [`verify::Toolchains::search_dirs`]); `mounts` names
/// the real host-to-sandbox mapping for whichever of those search dirs the
/// verifier actually binds as part of a larger, multi-directory mount (a
/// search dir with no matching entry here is judged as its own, self-mapped
/// boundary instead — see [`resolve_in_dirs`]'s doc for the full reasoning
/// [`resolve_in_dirs`] uses this for).
fn check_with_dirs_and_roots(
    dir: &Path,
    search_dirs: &[PathBuf],
    mounts: &[verify::Mount],
) -> Report {
    let ecosystem = Ecosystem::detect(dir);
    let mut rows = vec![policy_row(dir)];
    let (verify_row, config) = verify_row(dir);
    let unavailable = config.is_none();
    rows.push(verify_row);
    if let Some(config) = &config {
        // The worktree itself is always bind-mounted at `/work`
        // (`sandbox::Launch::args`), regardless of which toolchain mounts
        // `mounts` carries — an absolute symlink hop naming it (see
        // `runtime_row`'s doc) needs this known everywhere `runtime_row`
        // resolves a candidate, not just when a caller happens to pass it.
        let mut all_mounts = vec![verify::Mount {
            host: dir.to_path_buf(),
            sandbox: PathBuf::from(crate::sandbox::WORK_ROOT),
        }];
        all_mounts.extend_from_slice(mounts);
        rows.push(runtime_row(
            dir,
            &config.verify.command,
            search_dirs,
            &all_mounts,
        ));
        rows.push(protected_row(dir, config));
    }
    Report {
        ecosystem,
        rows,
        unavailable,
    }
}

fn policy_row(dir: &Path) -> Row {
    let path = dir.join(".ward/policy.yaml");
    match std::fs::read_to_string(&path) {
        Ok(yaml) => match ward_policy::Policy::from_yaml(&yaml) {
            Ok(_) => Row::new("policy", Status::Ok, ".ward/policy.yaml resolves"),
            Err(e) => Row::new(
                "policy",
                Status::Fail,
                format!(".ward/policy.yaml: {e}; a session cannot resolve its policy"),
            ),
        },
        // Absent is the ordinary pre-`ward init` state; any other I/O failure (the
        // path is a directory, permission denied, …) means the policy genuinely
        // cannot be read and must not be reported as a harmless "not written yet".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Row::new(
            "policy",
            Status::Warn,
            "not written yet; `ward init` writes secure defaults",
        ),
        Err(e) => Row::new(
            "policy",
            Status::Fail,
            format!(".ward/policy.yaml: {e}; a session cannot resolve its policy"),
        ),
    }
}

/// The verify-config row, and the parsed config when one could be read — `None`
/// triggers `Verdict::Unavailable` and skips the rows that need a real command
/// (`runtime`, `protected paths`), tracked separately from a merely failing row so
/// the two stay distinguishable in the overall verdict.
fn verify_row(dir: &Path) -> (Row, Option<verify::Config>) {
    let path = dir.join(verify::CONFIG_PATH);
    let yaml = match std::fs::read_to_string(&path) {
        Ok(y) => y,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                Row::new(
                    "verify config",
                    Status::Fail,
                    format!(
                        "{} not written yet; `ward init` writes a guess",
                        verify::CONFIG_PATH
                    ),
                ),
                None,
            );
        }
        Err(e) => {
            return (
                Row::new(
                    "verify config",
                    Status::Fail,
                    format!("{}: {e}", verify::CONFIG_PATH),
                ),
                None,
            );
        }
    };
    match verify::Config::parse(&yaml) {
        Ok(config) => {
            let row = Row::new(
                "verify config",
                Status::Ok,
                format!("command: {}", config.verify.command),
            );
            (row, Some(config))
        }
        Err(_) => (
            Row::new(
                "verify config",
                Status::Fail,
                format!(
                    "{} has no verify.command; name the test command before an agent starts",
                    verify::CONFIG_PATH
                ),
            ),
            None,
        ),
    }
}

/// Shell syntax whose presence means `verify.command` is outside the narrow
/// simple-command grammar [`runtime_row`] resolves: pipelines and lists (`|`,
/// `&`, `;`), redirection (`<`, `>`), substitution and parameter expansion
/// (`` ` ``, `$`), and quoting or escaping (`"`, `'`, `\`) — the last because a
/// quoted token like `"cargo"` is not the literal program name `"cargo"` (quotes
/// included) that whitespace-splitting alone would produce. A command containing
/// any of these has no single "the program" this check can name with confidence,
/// so `runtime_row` reports it indeterminate rather than guessing at or
/// mis-splitting it — `cd subdir && cargo test` must not be judged runnable or
/// not by probing the literal token `cd`.
const SHELL_METACHARACTERS: &[&str] = &["|", "&", ";", "<", ">", "`", "$", "\"", "'", "\\"];

/// Builtins and keywords a shell resolves itself, never via `PATH`, so `which`
/// would wrongly report them absent. Deliberately small: only ones in common use
/// at the start of a verify command that do not also exist as a real binary on a
/// typical system (`true`, `test`, `[` usually do and are left to the `PATH`
/// check, which finds them correctly either way).
const SHELL_BUILTINS: &[&str] = &[
    "cd", "exec", "eval", "export", "unset", "set", "shift", "source", ".", ":", "type", "alias",
    "unalias", "trap", "wait", "return",
];

/// Whether `token` is a POSIX environment-variable assignment prefix (`NAME=value`,
/// e.g. `FOO=bar` in `FOO=bar cargo test`) rather than the command itself.
fn is_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `path` is a regular file the *invoking process* can actually
/// execute — what `/bin/sh -c` itself needs before it can start it. Delegates
/// to the kernel's own `access(2)` (`X_OK`) rather than testing permission bits
/// directly: a coarse `mode & 0o111 != 0` is wrong on both sides — a directory
/// commonly has every execute ("search") bit set without being a runnable
/// program, and a file whose *matching* owner/group/other class has no execute
/// bit is not executable by this process even if some other class's bit is set
/// (e.g. group-execute-only when the process is not in that group). `access(2)`
/// resolves the correct class (and, on Linux, root's own "any class" rule) the
/// same way the shell's own exec will.
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
        && nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

/// Whether `path` resolves to somewhere *outside* `root` — checked lexically
/// after symlinks are already accounted for by
/// [`resolve_symlinks_conservatively`], so this only catches what's left once
/// every hop has already been individually vetted: a literal `..` escape in
/// the configured path itself (`verify.command: ../../etc/passwd`, no
/// symlink involved at all), or a chain of *relative* symlink hops that,
/// hop by hop, each looked legitimate (resolved against its own containing
/// directory, exactly what a bind mount preserves) but whose cumulative
/// destination walked straight out of the one root the verifier actually
/// mounts at this path — a root the caller is responsible for choosing:
/// the project worktree for a project-relative candidate, or a single
/// search directory for a bare one resolved against
/// [`verify::Toolchains::search_dirs`]. `false` when either side fails to
/// canonicalize (typically: `path` does not exist) — a plain absence, for
/// the caller's own not-found handling, not an escape.
fn escapes_root(root: &Path, path: &Path) -> bool {
    match (root.canonicalize(), path.canonicalize()) {
        (Ok(root_real), Ok(path_real)) => !path_real.starts_with(&root_real),
        _ => false,
    }
}

/// The kernel's own `ELOOP` hop limit — bounds [`resolve_symlinks_conservatively`]
/// so a symlink cycle cannot hang it.
const MAX_SYMLINK_HOPS: u8 = 40;

/// What following `path` through its symlinks (if it is one, or leads through
/// one) can prove about how it resolves *inside the verifier's own mount
/// namespace* — not merely on the host, which is a different question once a
/// symlink is involved (see [`runtime_row`]'s doc for why).
#[derive(Clone, Debug, PartialEq, Eq)]
enum LinkResolution {
    /// Every hop was safe to reason about, and this is the final, real
    /// (non-symlink) host path — still needs its own existence/executability
    /// and, for a project-relative candidate, worktree-containment checked.
    /// The second field is the same destination re-expressed in **sandbox**
    /// coordinates, when the caller passed a starting sandbox position (see
    /// [`resolve_symlinks_conservatively`]'s `shadow` parameter) — `None`
    /// when it didn't ask for one (project-relative/absolute candidates,
    /// which don't need it).
    Resolved(PathBuf, Option<PathBuf>),
    /// Some hop does not exist at all (a plain absence, not a broken link).
    Missing,
    /// A hop's symlink target was an absolute path outside both `SYSTEM_RO`
    /// and every known [`verify::Mount`]'s sandbox directory, or the chain
    /// cycled/ran past [`MAX_SYMLINK_HOPS`] — either way, this is a
    /// *definite* fact about the verifier's fixed, fully-enumerable mount set,
    /// not a guess: the target (or the cycle itself, which `/bin/sh -c` would
    /// hit identically) is guaranteed broken inside the sandbox, the same
    /// certainty an absolute candidate outside every known mount already gets.
    Broken,
}

/// Resolves `path` **component by component**, the way the kernel's own path
/// lookup does — not just the final component, which is all
/// `Path::symlink_metadata`/`canonicalize` alone can distinguish. A directory
/// component partway through a path can itself be a symlink (`bin -> ../tools`,
/// then `./bin/verify.sh`), and the kernel follows that hop exactly as it would
/// follow one at the very end; checking only the leaf would miss it entirely —
/// a regular file at the end is not proof that nothing above it redirected the
/// walk somewhere the verifier does not mount.
///
/// At every symlink hop, only the shapes a bind-mounted worktree, a toolchain
/// mount, or a `SYSTEM_RO` directory actually preserve are trusted: a
/// **relative** target (resolved against its own containing directory, then
/// re-walked the same way) resolves identically wherever the containing
/// directory ends up mounted, exactly what bind-mounting a directory
/// preserves about its own internal relative symlinks; an **absolute**
/// target resolves the same way inside the sandbox in exactly two cases —
/// when it is itself [`crate::sandbox::is_system_ro`] (mounted read-only at
/// the identical path on the host and inside every sandbox — resolution then
/// continues from that root), or when it names one of the *known*
/// [`verify::Mount`]s' own `sandbox` directory (e.g. `/work`, the worktree
/// itself; or a toolchain directory under `/run/verifier`) — resolution then
/// continues from that mount's `host` directory instead, since that is where
/// the *contents* the verifier would see there actually live on this host,
/// even though the literal sandbox path the symlink names may not exist on
/// the host at all (the worktree's own `/work` binding is a prime example —
/// a symlink naming it is only ever meant to be followed *inside* the
/// verifier). Any other absolute target — most commonly one carrying the
/// worktree's own host temp-directory prefix, or a toolchain directory's
/// real host location, neither of which the sandbox mounts at that literal
/// path — is [`LinkResolution::Broken`]: the sandbox's mount set is fixed
/// and fully enumerable, so an absolute target outside it is not merely
/// unverified, it is *guaranteed absent*.
/// `path`'s components, `.`/`/` dropped — what's left is `..` and real names,
/// in the order [`resolve_symlinks_conservatively`] needs to consume them.
fn components_of(path: &Path) -> std::collections::VecDeque<PathBuf> {
    use std::path::Component;
    path.components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .map(|c| PathBuf::from(c.as_os_str()))
        .collect()
}

/// `shadow`, when given, is the *sandbox* position that corresponds to
/// `path`'s own starting directory (e.g. `dir`'s `verify::Mount::sandbox`, or
/// `dir` itself when the verifier sees it at an identical path) — every pop
/// and push this walk applies to `resolved` (in host coordinates) is applied
/// to `shadow` too, in lockstep, so the two accumulators only ever diverge
/// where the *real* host and sandbox mount layouts do: at an absolute hop
/// (reset to `/` on both sides, since [`crate::sandbox::is_system_ro`] means
/// identically-placed) and at root saturation, which each side's own
/// [`PathBuf::pop`] applies independently. This is deliberately a parallel
/// walk of the exact textual navigation, not a diff of the two final
/// destinations after the fact — the destinations alone cannot tell apart a
/// symlink whose `..`s stop just short of one side's root from one whose
/// `..`s run past it (see [`resolve_in_dirs`]'s doc for the reproduction
/// this distinction exists to catch).
fn resolve_symlinks_conservatively(
    path: PathBuf,
    shadow: Option<PathBuf>,
    mounts: &[verify::Mount],
) -> LinkResolution {
    // The walk below always starts from "/"; a caller-relative `dir` (`ward
    // ready ../other-project`) would otherwise resolve against the wrong
    // root entirely. `std::fs::canonicalize`'s own absolutising behavior is
    // what every other relative-path std::fs call already does implicitly
    // (resolve against the process's cwd); a path that does not exist yet
    // falls through to plain concatenation, deferring to the Missing/Broken
    // handling below, which `read_link`/`symlink_metadata` on a nonexistent
    // component reaches on its own.
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_or_else(|_| path.clone(), |cwd| cwd.join(&path))
    };
    walk_symlinks(components_of(&path), PathBuf::from("/"), shadow, mounts)
}

/// Continues the exact same conservative walk [`resolve_symlinks_conservatively`]
/// performs, but starting from an already-resolved `(base, base_shadow)`
/// position instead of `/` and `rest`'s own components instead of a whole
/// path's. [`resolve_in_dirs`] uses this to anchor `shadow` mirroring exactly
/// at `dir`'s own resolved boundary — found by first resolving `dir` alone,
/// with no `shadow` — rather than walking `dir`'s own ancestor components a
/// *second* time under `shadow` from `/`, which would push them onto
/// `shadow` on top of the `dir_sandbox` position it already starts at,
/// double-counting `dir`'s own path onto its sandbox counterpart.
fn resolve_relative_conservatively(
    base: PathBuf,
    base_shadow: Option<PathBuf>,
    rest: &Path,
    mounts: &[verify::Mount],
) -> LinkResolution {
    walk_symlinks(components_of(rest), base, base_shadow, mounts)
}

/// Where an absolute symlink `target` starts resolving from, if anywhere the
/// verifier makes visible — the `(host base, sandbox base, remaining
/// components)` a caller re-walks one at a time from that base, exactly like
/// a relative target continuing from its own containing directory (so an
/// intermediate component the base-plus-suffix join would otherwise skip
/// checking still gets its own symlink hop looked at): on the host at the
/// identical path ([`crate::sandbox::is_system_ro`] — both bases are `/`,
/// and every one of `target`'s own components remains to walk, exactly the
/// existing identity-mount behavior), under a known [`verify::Mount`] (both
/// bases are that mount's `host`/`sandbox` directories, and only whatever of
/// `target` remained past its `sandbox` prefix is left to walk), or nowhere
/// (`None`, [`LinkResolution::Broken`]).
fn absolute_target_mount(
    target: &Path,
    mounts: &[verify::Mount],
) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if crate::sandbox::is_system_ro(target) {
        return Some((PathBuf::from("/"), PathBuf::from("/"), target.to_path_buf()));
    }
    let mount = mounts.iter().find(|m| target.starts_with(&m.sandbox))?;
    let suffix = target.strip_prefix(&mount.sandbox).ok()?.to_path_buf();
    Some((mount.host.clone(), mount.sandbox.clone(), suffix))
}

fn walk_symlinks(
    mut todo: std::collections::VecDeque<PathBuf>,
    mut resolved: PathBuf,
    mut shadow: Option<PathBuf>,
    mounts: &[verify::Mount],
) -> LinkResolution {
    let mut hops = 0u8;
    while let Some(component) = todo.pop_front() {
        if component.as_os_str() == ".." {
            resolved.pop();
            if let Some(s) = shadow.as_mut() {
                s.pop();
            }
            continue;
        }
        let candidate = resolved.join(&component);
        let Ok(meta) = candidate.symlink_metadata() else {
            return LinkResolution::Missing;
        };
        if !meta.file_type().is_symlink() {
            resolved = candidate;
            if let Some(s) = shadow.as_mut() {
                s.push(&component);
            }
            continue;
        }
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return LinkResolution::Broken;
        }
        let Ok(target) = std::fs::read_link(&candidate) else {
            return LinkResolution::Missing;
        };
        let rest = if target.is_absolute() {
            let Some((host_base, sandbox_base, suffix)) = absolute_target_mount(&target, mounts)
            else {
                return LinkResolution::Broken;
            };
            resolved = host_base;
            if let Some(s) = shadow.as_mut() {
                *s = sandbox_base;
            }
            suffix
        } else {
            // A relative target continues from `resolved` (its symlink's own
            // containing directory) unchanged.
            target
        };
        for c in components_of(&rest).into_iter().rev() {
            todo.push_front(c);
        }
    }
    LinkResolution::Resolved(resolved, shadow)
}

/// Whether the binary the *configured* `verify.command` would actually invoke is
/// available — checked against the real command, not guessed from the project
/// manifest, so a Cargo project configured to run `npm test` is checked against
/// `npm`, and one running a custom `bash scripts/…` is checked against `bash`, not
/// against `cargo` either way.
///
/// Deliberately narrow: only a single simple command — optionally prefixed with
/// `NAME=value` assignments, as `FOO=bar cargo test` is — is resolved. A command
/// containing any [`SHELL_METACHARACTERS`] or led by a shell builtin
/// ([`SHELL_BUILTINS`]) is reported indeterminate rather than misjudged: no PATH
/// search can tell whether `cd subdir && cargo test` is runnable without a real
/// shell, and a quoted token like `"cargo"` must not be probed as the literal
/// (quote-included) name it splits to. A path candidate (containing `/`, e.g.
/// `./scripts/verify.sh`) is resolved against `dir` — the verifier's own working
/// directory, not `search_dirs` — and must itself be executable, the same
/// precondition `/bin/sh -c` enforces. A bare candidate is searched in
/// `search_dirs` the same way, and must be executable there too.
///
/// `search_dirs` is the verifier's own search directories
/// ([`verify::Toolchains::search_dirs`]), never the calling process's `PATH`:
/// `ward verify` runs the command in a sandbox whose `PATH` is replaced with
/// the mounted Cargo toolchain (if any) and the base system directories, not
/// inherited from whoever ran `ward ready`. A program on the caller's own
/// `PATH` that isn't in one of these directories would not be found inside the
/// verifier either, and a Cargo toolchain that *is* mounted there is available
/// to the verifier even when `$CARGO_HOME/bin` is not on the caller's `PATH`.
fn runtime_row(
    dir: &Path,
    command: &str,
    search_dirs: &[PathBuf],
    mounts: &[verify::Mount],
) -> Row {
    if let Some(op) = SHELL_METACHARACTERS.iter().find(|op| command.contains(*op)) {
        return Row::new(
            "runtime",
            Status::Warn,
            format!("verify.command contains `{op}`; runtime availability not verified"),
        );
    }
    let Some(candidate) = command.split_whitespace().find(|t| !is_assignment(t)) else {
        return Row::new(
            "runtime",
            Status::Warn,
            "verify.command is blank or only environment assignments; cannot determine a runtime",
        );
    };
    if SHELL_BUILTINS.contains(&candidate) {
        return Row::new(
            "runtime",
            Status::Warn,
            format!(
                "verify.command starts with the shell builtin `{candidate}`; runtime availability not verified"
            ),
        );
    }
    if candidate.contains('/') {
        return path_candidate_row(dir, candidate, mounts);
    }
    match resolve_in_dirs(candidate, search_dirs, mounts) {
        PathLookup::Executable => Row::new(
            "runtime",
            Status::Ok,
            format!("{candidate} available to the verifier"),
        ),
        PathLookup::Broken => Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} is a symlink pointing somewhere the verifier does not mount; it will not exist inside the sandbox"
            ),
        ),
        PathLookup::NotExecutable => Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} found but not executable in the verifier's environment; fix its permissions before `ward verify` can run"
            ),
        ),
        PathLookup::Missing => Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} not found in the verifier's environment ({}); install it where the verifier can reach it before `ward verify` can run",
                search_dirs
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":")
            ),
        ),
    }
}

/// [`runtime_row`]'s path-candidate case (`candidate` contains `/`): resolved
/// against `dir` when relative, checked against [`crate::sandbox::is_system_ro`]
/// when absolute, and validated through [`resolve_symlinks_conservatively`]
/// either way before the final executability check.
fn path_candidate_row(dir: &Path, candidate: &str, mounts: &[verify::Mount]) -> Row {
    let absolute = Path::new(candidate).is_absolute();
    let path = if absolute {
        PathBuf::from(candidate)
    } else {
        dir.join(candidate)
    };
    if absolute && !crate::sandbox::is_system_ro(&path) {
        return Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} is outside the verifier's read-only system mounts; it will not exist inside the sandbox (/tmp, /home and /run are private and empty there)"
            ),
        );
    }
    // An absolute candidate starts as an identity sandbox position (just
    // proved `is_system_ro` above), tracked through the walk so a later hop
    // into a *non*-identity mount (`/work`, a toolchain directory) is
    // judged correctly rather than by the coarse "is the final host path
    // still `is_system_ro`" check this replaced (which a legitimate jump
    // into such a mount would fail even though the destination is real).
    // Starts at `/`, matching `resolved`'s own start inside
    // `resolve_symlinks_conservatively` (which always walks the *whole*
    // absolutized `path` from root) — not at `path` itself, which would
    // double-push every one of `path`'s own components onto `shadow` on
    // top of a starting point that already included them. A
    // project-relative candidate doesn't need this: `escapes_root(dir,
    // ...)` below already judges its containment directly on the (now
    // correctly translated) host destination.
    let shadow_start = absolute.then(|| PathBuf::from("/"));
    let (resolved, shadow) = match resolve_symlinks_conservatively(
        path.clone(),
        shadow_start,
        mounts,
    ) {
        LinkResolution::Resolved(p, s) => (p, s),
        LinkResolution::Broken => {
            return Row::new(
                "runtime",
                Status::Fail,
                format!(
                    "{candidate} is a symlink pointing somewhere the verifier does not mount; it will not exist inside the sandbox"
                ),
            );
        }
        LinkResolution::Missing => {
            let message = if absolute {
                format!("{candidate} not found; fix the path before `ward verify` can run")
            } else {
                format!(
                    "{candidate} not found relative to the project; fix the path before `ward verify` can run"
                )
            };
            return Row::new("runtime", Status::Fail, message);
        }
    };
    if !absolute && escapes_root(dir, &resolved) {
        return Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} resolves outside the project; it will not exist inside the verifier, which only sees the worktree itself"
            ),
        );
    }
    // The initial-candidate `is_system_ro` check above only proves *this*
    // path starts inside a mounted root — a relative symlink hop the walk
    // just followed can still have carried it back out (e.g. `/usr/local/bin/x
    // -> ../../../home/evil`), landing somewhere the sandbox never mounts even
    // though the literal candidate looked safe. The fully resolved
    // destination needs the same guarantee the candidate itself just got —
    // now judged in sandbox coordinates via `shadow`, so a hop that lands in
    // a known non-identity mount (rather than back in `SYSTEM_RO`) is
    // correctly accepted too.
    if absolute {
        let contained = shadow.as_ref().is_some_and(|s| {
            crate::sandbox::is_system_ro(s) || mounts.iter().any(|m| s.starts_with(&m.sandbox))
        });
        if !contained {
            return Row::new(
                "runtime",
                Status::Fail,
                format!(
                    "{candidate} is a symlink pointing somewhere the verifier does not mount; it will not exist inside the sandbox"
                ),
            );
        }
    }
    // `resolved`, not the original `path`: a symlink translated through a
    // known mount (e.g. `./bin/verify.sh -> /work/tools/verify.sh`) can be
    // genuinely executable inside the verifier while the literal host path
    // is correctly broken outside it (`/work` is a sandbox-only bind).
    if is_executable(&resolved) {
        Row::new(
            "runtime",
            Status::Ok,
            format!("{candidate} present and executable"),
        )
    } else {
        Row::new(
            "runtime",
            Status::Fail,
            format!(
                "{candidate} exists but is not executable (or is a directory); chmod +x it, or name a program inside it, before `ward verify` can run"
            ),
        )
    }
}

/// The outcome of searching `search_dirs` for a candidate: present and
/// runnable, a symlink guaranteed broken inside the verifier's mount
/// namespace, present but not executable, or not found at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathLookup {
    Missing,
    NotExecutable,
    Broken,
    Executable,
}

/// Search `search_dirs`, in order, for an executable file named `candidate`,
/// following [`resolve_symlinks_conservatively`]'s same rules for any symlink
/// along the way. Distinguishes "not found anywhere" from "found, but not
/// executable" from "found, but only through a symlink the verifier's mount
/// set guarantees is broken" so [`runtime_row`] can name the real problem.
///
/// A relative symlink hop the walk follows can carry the final destination
/// out of the specific `dir` that found it (`<home>/bin/cargo ->
/// ../../outside/cargo`) without ever pointing through an absolute target —
/// nothing the hop-by-hop walk itself checks catches that, since a relative
/// target is, correctly, allowed to resolve wherever its own containing
/// directory ends up mounted. Whether the destination is legitimate has to be
/// judged in **sandbox** coordinates, not by whether the resolved *host* path
/// merely sits under some other host directory the verifier separately
/// mounts: `$CARGO_HOME/bin/tool -> ../../../usr/bin/true` resolves, on the
/// host, to the real `/usr/bin/true` (three `..`s from a typical
/// `$CARGO_HOME/bin` reach the host's own root) — `is_system_ro` and
/// genuinely executable there, so a host-only check accepts it. Inside the
/// verifier, though, that same relative target is followed from
/// `/run/verifier/cargo/bin`, and three `..`s from there reach only `/run`
/// (one level short of the sandbox's own root, since Cargo's mount sits four
/// components deep) — the walk lands on `/run/usr/bin/true`, which nothing
/// binds. The two namespaces don't share a directory hierarchy above the
/// bind points themselves, so `dir` is resolved once on its own first (its
/// own ancestor components may themselves need following — an existing,
/// separate ancestor-symlink case — but never need `shadow`, since nothing
/// before `dir` itself changes which mount its *contents* land under), and
/// only `candidate`'s own components continue the walk from `dir`'s real
/// host position *and* its sandbox position together
/// ([`resolve_relative_conservatively`]), carrying both accumulators in
/// lockstep from that shared anchor. This never reconstructs the sandbox
/// destination afterward from two final endpoints alone (an earlier version
/// of this function tried exactly that, diffing `dir`'s and the resolved
/// candidate's canonicalized components; it silently loses however many
/// `..`s ran past *either* side's own root before the walk stopped, so a
/// symlink whose `..` count saturates the host root one hop earlier or later
/// than it saturates the sandbox root cannot be told apart from one that
/// doesn't — replaying only the *shortest* endpoint-to-endpoint delta gets
/// exactly that case wrong).
fn resolve_in_dirs(
    candidate: &str,
    search_dirs: &[PathBuf],
    mounts: &[verify::Mount],
) -> PathLookup {
    let mut found_non_executable = false;
    for dir in search_dirs {
        let dir_sandbox = mounts
            .iter()
            .find(|m| &m.host == dir)
            .map_or_else(|| dir.clone(), |m| m.sandbox.clone());
        let dir_real = match resolve_symlinks_conservatively(dir.clone(), None, mounts) {
            LinkResolution::Resolved(p, _) => p,
            LinkResolution::Broken => return PathLookup::Broken,
            LinkResolution::Missing => continue,
        };
        let resolution = resolve_relative_conservatively(
            dir_real,
            Some(dir_sandbox.clone()),
            Path::new(candidate),
            mounts,
        );
        match resolution {
            LinkResolution::Broken => return PathLookup::Broken,
            LinkResolution::Resolved(resolved, shadow) if resolved.is_file() => {
                // Always `Some`: this call site always passes a `shadow` start.
                let Some(sandbox_candidate) = shadow else {
                    return PathLookup::Broken;
                };
                let contained = crate::sandbox::is_system_ro(&sandbox_candidate)
                    || sandbox_candidate.starts_with(&dir_sandbox)
                    || mounts
                        .iter()
                        .any(|m| sandbox_candidate.starts_with(&m.sandbox));
                if !contained {
                    return PathLookup::Broken;
                }
                // `resolved`, not `candidate_path`: a symlink translated
                // through a known mount (e.g. `bin/cargo ->
                // /run/verifier/cargo/registry/cargo`) can be genuinely
                // executable inside the verifier while the literal host
                // path is correctly broken outside it.
                if is_executable(&resolved) {
                    return PathLookup::Executable;
                }
                found_non_executable = true;
            }
            LinkResolution::Missing | LinkResolution::Resolved(..) => {}
        }
    }
    if found_non_executable {
        PathLookup::NotExecutable
    } else {
        PathLookup::Missing
    }
}

fn protected_row(dir: &Path, config: &verify::Config) -> Row {
    if config.protected.tests.is_empty() {
        return Row::new(
            "protected paths",
            Status::Warn,
            "protected.tests is empty; the verifier has nothing to restore across a run",
        );
    }
    let missing: Vec<&str> = config
        .protected
        .tests
        .iter()
        .map(String::as_str)
        .filter(|p| !dir.join(p).exists())
        .collect();
    if missing.is_empty() {
        Row::new(
            "protected paths",
            Status::Ok,
            format!("{} path(s) present", config.protected.tests.len()),
        )
    } else {
        Row::new(
            "protected paths",
            Status::Warn,
            format!("not yet on disk: {}", missing.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn resolve_symlinks_conservatively_treats_an_absolute_non_system_target_as_broken() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("tool"), "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(outside.path().join("tool"), &link).unwrap();
        assert_eq!(
            resolve_symlinks_conservatively(link, None, &[]),
            LinkResolution::Broken
        );
    }

    #[test]
    fn resolve_symlinks_conservatively_treats_an_absolute_system_ro_target_as_resolved() {
        // /usr/bin/bash is as close to universal as a fixture can get, and /usr
        // is unconditionally in SYSTEM_RO: exactly the "safe absolute hop" case.
        let real = Path::new("/usr/bin/bash");
        if !real.is_file() {
            return; // not present on this machine; the Broken-case test above
            // already covers the mechanism this one exists to contrast with.
        }
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(real, &link).unwrap();
        assert_eq!(
            resolve_symlinks_conservatively(link, None, &[]),
            LinkResolution::Resolved(real.to_path_buf(), None)
        );
    }

    #[test]
    fn a_freshly_initialised_cargo_project_is_ready_or_limited_never_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".ward/policy.yaml",
            ward_policy::Policy::template(),
        );
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - tests/\nverify:\n  command: cargo test\n",
        );
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        let report = check(dir.path());
        assert_eq!(report.ecosystem, Ecosystem::Cargo);
        // `cargo` may or may not be in the verifier's search dirs on this machine;
        // either way the verdict must never be `Unavailable` (a command *is*
        // configured) and never silently skip a row.
        assert_ne!(report.verdict(), Verdict::Unavailable);
        assert!(report.rows.iter().any(|r| r.name == "policy"));
        assert!(report.rows.iter().any(|r| r.name == "verify config"));
        assert!(report.rows.iter().any(|r| r.name == "runtime"));
        assert!(report.rows.iter().any(|r| r.name == "protected paths"));
    }

    #[test]
    fn no_ward_init_at_all_is_unavailable_not_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Unavailable);
        // Unavailable stops before the protected-paths row: there is no config to
        // read a protected list from.
        assert!(!report.rows.iter().any(|r| r.name == "protected paths"));
    }

    #[test]
    fn a_verify_config_with_no_command_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests: []\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Unavailable);
    }

    #[test]
    fn empty_protected_tests_is_limited_not_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited);
        let row = report
            .rows
            .iter()
            .find(|r| r.name == "protected paths")
            .unwrap();
        assert_eq!(row.status, Status::Warn);
        assert!(row.detail.contains("nothing to restore"));
    }

    #[test]
    fn a_protected_path_not_yet_on_disk_is_limited() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - tests/\nverify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited);
        let row = report
            .rows
            .iter()
            .find(|r| r.name == "protected paths")
            .unwrap();
        assert!(row.detail.contains("tests/"), "{}", row.detail);
    }

    #[test]
    fn a_malformed_policy_is_setup_required_not_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".ward/policy.yaml", "network: [not, a, mode]\n");
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::SetupRequired);
        let row = report.rows.iter().find(|r| r.name == "policy").unwrap();
        assert_eq!(row.status, Status::Fail);
    }

    #[test]
    fn an_unreadable_policy_is_setup_required_not_a_harmless_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // A directory sitting at the policy's path is not "not written yet" — it is
        // unreadable, and must not be reported as the same harmless absence.
        std::fs::create_dir_all(dir.path().join(".ward/policy.yaml")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "policy").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_checks_the_configured_command_not_the_manifest_guess() {
        let dir = tempfile::tempdir().unwrap();
        // A Cargo project can still configure a different verifier command; the
        // runtime row must judge that command, not assume `cargo` from Cargo.toml.
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: npm test\n",
        );
        // An empty, controlled search list: deterministic regardless of whatever
        // toolchain the machine running this test happens to have, and proves the
        // row names the real candidate even when unresolved.
        let report = check_with_dirs(dir.path(), &[]);
        assert_eq!(report.ecosystem, Ecosystem::Cargo);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert!(row.detail.starts_with("npm"), "{}", row.detail);
    }

    #[test]
    fn runtime_checks_a_custom_shell_commands_own_first_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: bash scripts/verify.sh\n",
        );
        let report = check_with_dirs(dir.path(), &[]);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert!(row.detail.starts_with("bash"), "{}", row.detail);
    }

    #[test]
    fn runtime_skips_a_leading_environment_assignment() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: FOO=bar cargo test\n",
        );
        let search_dir = tempfile::tempdir().unwrap();
        let cargo_bin = search_dir.path().join("cargo");
        std::fs::write(&cargo_bin, "not a real binary").unwrap();
        make_executable(&cargo_bin);

        // A controlled search dir containing `cargo`, not the real environment's:
        // deterministic regardless of the machine running this test. A correct
        // implementation resolves past `FOO=bar` to a real Ok against `cargo`,
        // not a Fail against the literal token `FOO=bar`.
        let dirs = [search_dir.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert!(row.detail.contains("cargo"), "{}", row.detail);
        assert!(!row.detail.contains("FOO"), "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `rm -rf` on drop, for a fixture directory a test plants outside its own
    /// `tempfile::tempdir()` (e.g. under a real `SYSTEM_RO` root it doesn't own).
    struct RemoveDirOnDrop(PathBuf);
    impl Drop for RemoveDirOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_bare_command_found_in_a_search_dir_but_not_executable_is_setup_required() {
        // A controlled search directory, not the process's real PATH: a mode-0644
        // regular file named `cargo` sits where a real search would find it, but
        // `/bin/sh -c 'cargo test'` cannot execute it — the same false-ready class
        // the project-relative branch's executable check already prevents. Passed
        // explicitly to check_with_dirs rather than mutating the process-global
        // environment, which would be unsound alongside tests running in parallel.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let search_dir = tempfile::tempdir().unwrap();
        std::fs::write(search_dir.path().join("cargo"), "not a real binary").unwrap();

        let dirs = [search_dir.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert!(row.detail.contains("not executable"), "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);

        // The same controlled directory with the file actually made executable: Ok.
        make_executable(&search_dir.path().join("cargo"));
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_search_dir_entry_symlinked_to_an_unmounted_target_as_setup_required() {
        // A `cargo` sitting in a search dir (mirroring a mounted toolchain
        // bin/) that is itself a symlink to a real, executable file elsewhere
        // on the host is host-executable, but the verifier's own mounts do not
        // cover that elsewhere — the same broken-link class an absolute system
        // candidate or a project-relative one can hit too.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let search_dir = tempfile::tempdir().unwrap();
        let real_elsewhere = tempfile::tempdir().unwrap();
        let real_cargo = real_elsewhere.path().join("cargo");
        std::fs::write(&real_cargo, "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&real_cargo);
        std::os::unix::fs::symlink(&real_cargo, search_dir.path().join("cargo")).unwrap();

        let dirs = [search_dir.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_an_absolute_ancestor_symlink_in_the_worktree_as_setup_required() {
        // The leaf, `verify.sh`, is a plain executable regular file — a
        // leaf-only check would stop right there and say Ok. But `bin` itself,
        // an *ancestor* directory of the configured path, is an absolute
        // symlink to another directory inside the same project; the kernel's
        // own path lookup follows that hop exactly as it would follow one at
        // the very end, and it carries the worktree's own host temp-directory
        // prefix, which the sandbox never mounts at that literal path.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tools/verify.sh", "#!/bin/sh\ntrue\n");
        make_executable(&dir.path().join("tools/verify.sh"));
        std::os::unix::fs::symlink(dir.path().join("tools"), dir.path().join("bin")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./bin/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_an_ancestor_symlink_in_a_search_dir_targeting_an_unmounted_location_as_setup_required()
     {
        // Mirrors a toolchain bin/ (or a directory under /usr/local) whose
        // *containing* directory, not the binary itself, is a symlink to a
        // real host location the verifier does not separately mount at that
        // path — the same ancestor-hop gap, reached through resolve_in_dirs's
        // own search instead of the project-relative branch.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let real_elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(real_elsewhere.path().join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&real_elsewhere.path().join("cargo"));
        let search_root = tempfile::tempdir().unwrap();
        let search_bin = search_root.path().join("bin");
        std::os::unix::fs::symlink(real_elsewhere.path(), &search_bin).unwrap();

        let dirs = [search_bin];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_relative_symlink_escaping_its_search_dir_as_setup_required() {
        // `cargo` itself (the leaf, not an ancestor) is a *relative* symlink
        // whose target, resolved against its own containing directory (the
        // search dir — exactly what a bind mount of that directory would
        // preserve), still walks straight out of it via `..`. The earlier
        // ancestor-symlink test above covers a *directory* hop redirecting the
        // walk; this covers the leaf link itself netting outside the one root
        // that makes it visible at all — nothing about it is an absolute
        // target, so the hop-by-hop walk's own `is_system_ro` check never
        // sees it, and it isn't under any real SYSTEM_RO root either.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let real_elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(real_elsewhere.path().join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&real_elsewhere.path().join("cargo"));
        let search_dir = tempfile::tempdir().unwrap();
        // search_dir/cargo -> ../<real_elsewhere's basename>/cargo: one level
        // up from search_dir reaches the shared base temp directory, then back
        // down into real_elsewhere — a relative chain, never an absolute hop.
        let relative_escape = PathBuf::from("..")
            .join(real_elsewhere.path().file_name().unwrap())
            .join("cargo");
        std::os::unix::fs::symlink(&relative_escape, search_dir.path().join("cargo")).unwrap();

        let dirs = [search_dir.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_allows_a_relative_symlink_that_stays_within_its_search_dir() {
        // Mirrors runtime_allows_a_project_relative_symlink_that_stays_within_the_worktree
        // for the search-dir branch: a relative target resolved against its
        // own containing directory, landing back inside that same search dir,
        // is exactly what a bind mount of the toolchain directory preserves —
        // this one must stay Ok, not get caught by the new containment check.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let search_dir = tempfile::tempdir().unwrap();
        write(search_dir.path(), "real/cargo", "#!/bin/sh\ntrue\n");
        make_executable(&search_dir.path().join("real/cargo"));
        std::os::unix::fs::symlink("real/cargo", search_dir.path().join("cargo")).unwrap();

        let dirs = [search_dir.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    /// The real sandbox destinations `Toolchains::mounts()` pairs a detected
    /// Cargo `bin`/`registry` with (`{TOOLCHAIN_ROOT}/cargo/{bin,registry}`)
    /// — used directly, not a shorter synthetic stand-in, so a test's `..`
    /// count is exercised against the sandbox's *real* nesting depth. A
    /// shallower fake path would let a pop that should stop short of the
    /// sandbox's own root instead bottom out there, silently hiding exactly
    /// the class of bug these tests exist to catch.
    fn cargo_mounts(bin: PathBuf, registry: PathBuf) -> [verify::Mount; 2] {
        [
            verify::Mount {
                host: bin,
                sandbox: PathBuf::from("/run/verifier/cargo/bin"),
            },
            verify::Mount {
                host: registry,
                sandbox: PathBuf::from("/run/verifier/cargo/registry"),
            },
        ]
    }

    #[test]
    fn runtime_allows_a_relative_symlink_from_a_cargo_bin_into_its_sibling_registry_mount() {
        // Review finding on #219: `search_dirs` for a real Cargo toolchain is
        // just `$CARGO_HOME/bin` (nothing else is ever searched for the
        // command), but `Toolchains::mount` binds `bin` *and* `registry` as
        // siblings under one shared private tmpfs — so a relative symlink
        // from `bin/` to `../registry/…` resolves inside the real sandbox
        // exactly as it does on the host, even though its destination sits
        // outside the narrower `search_dirs` entry that found it. Judging
        // containment against `search_dirs` alone (the bug this test would
        // have caught) rejects this legitimate case; the real mount picture
        // — passed separately here via `check_with_dirs_and_roots`, exactly
        // as `check` derives both from one real `Toolchains` — must not.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(registry.join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&registry.join("cargo"));
        std::os::unix::fs::symlink("../registry/cargo", bin.join("cargo")).unwrap();

        let search_dirs = [bin.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_still_rejects_a_relative_symlink_escaping_every_mount_not_just_search_dirs() {
        // The other half of the same fix: broadening containment to the real
        // mount picture must not become "anything under $CARGO_HOME" — only
        // the specific subdirectories the sandbox actually mounts. A symlink
        // to a third, unmounted sibling (`libexec/`, mirroring the review's
        // own hypothetical) stays Fail even though it's still nominally
        // "under" the same cargo home on the host.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        let libexec = cargo_home.path().join("libexec");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        std::fs::write(libexec.join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&libexec.join("cargo"));
        std::os::unix::fs::symlink("../libexec/cargo", bin.join("cargo")).unwrap();

        let search_dirs = [bin.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_cargo_bin_relative_symlink_reaching_a_host_system_binary_as_setup_required()
     {
        // Review finding on #219 (the deeper gap in the mount-picture fix
        // above): the earlier fix judged containment in *host* coordinates —
        // "does the resolved destination sit under some host root the
        // verifier also mounts somewhere" — which a relative chain can
        // satisfy by pure host-filesystem coincidence, without the identical
        // navigation being valid inside the verifier at all.
        //
        // `$CARGO_HOME/bin/tool -> ../../../usr/bin/true`: on the host,
        // three `..`s from a typical `$CARGO_HOME/bin` (two directories
        // below root) reach the host's own `/`, and descending into
        // `usr/bin/true` finds the real, `is_system_ro`, executable system
        // binary — a host-only check accepts this. Inside the verifier,
        // though, `bin/` is mounted at `/run/verifier/cargo/bin` (four
        // components deep); the *same* three `..`s only reach `/run`, one
        // level short of the sandbox's own root, and `/run/usr/bin/true` is
        // not bound to anything. This must be Fail, not Ok.
        let real_true = Path::new("/usr/bin/true");
        if !real_true.is_file() {
            return; // not present on this machine; the mechanism is covered
            // by the other absolute-system-ro fixtures elsewhere in this
            // file (e.g. resolve_symlinks_conservatively's own /usr/bin/bash
            // case), which use the identical environment-conditional shape.
        }
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("../../../usr/bin/true", bin.join("cargo")).unwrap();

        let search_dirs = [bin.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_allows_a_cargo_bin_relative_symlink_whose_extra_dot_dot_saturates_at_host_root() {
        // Review finding on #219 (the root-saturation gap in the mount-picture
        // fix above): an earlier version of this containment check inferred
        // the sandbox destination by diffing `dir`'s and `resolved`'s
        // *canonicalized* endpoints, which discards how many `..`s actually
        // ran past root on either side. A fourth `..` here is a no-op on the
        // host (three already reach `/` from a typical `$CARGO_HOME/bin`),
        // but the sandbox's own `/run/verifier/cargo/bin` is one component
        // deeper — its fourth `..` is the one that first reaches root, so the
        // *same* symlink is genuinely executable inside the verifier. Judging
        // this from the endpoints alone (as the earlier fix did) undercounts
        // the pops and lands one level short of root on the sandbox side,
        // wrongly reporting `SetupRequired` for a command `ward verify` can
        // actually run. This must be Ok, the mirror image of the three-`..`
        // case above staying Fail.
        let real_true = Path::new("/usr/bin/true");
        if !real_true.is_file() {
            return; // covered by the identical environment-conditional shape
            // used by the three-`..` case above and by
            // resolve_symlinks_conservatively's own /usr/bin/bash fixture.
        }
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("../../../../usr/bin/true", bin.join("cargo")).unwrap();

        let search_dirs = [bin.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_system_dir_relative_symlink_reaching_a_cargo_mount_host_directory_as_setup_required()
     {
        // The inverse shape: a relative link that starts in a real,
        // identity-mapped system search directory and, purely by host
        // filesystem coincidence, reaches a file that lives under a
        // directory `Toolchains` also separately mounts for Cargo. That
        // host-side coincidence proves nothing about the sandbox — `/opt`
        // and `/run/verifier/cargo` are unrelated namespaces there — so this
        // must stay Fail even though the exact same physical file is, from
        // Cargo's own `bin/`, legitimately reachable.
        let probe_root = Path::new("/opt");
        let marker = probe_root.join(format!("ward-readiness-mount-test-{}", std::process::id()));
        if std::fs::create_dir(&marker).is_err() {
            return; // no write access here; the mechanism is covered by the
            // Cargo-bin case above either way.
        }
        let _cleanup = RemoveDirOnDrop(marker.clone());
        assert!(
            crate::sandbox::is_system_ro(&marker),
            "/opt is unconditionally in SYSTEM_RO"
        );

        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(registry.join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&registry.join("cargo"));
        // marker/cargo -> a relative path out of `marker` (under real
        // SYSTEM_RO /opt) into cargo_home/registry — built the same way the
        // existing absolute-candidate escape test elsewhere in this file
        // builds its relative target.
        let mut relative_escape = PathBuf::new();
        for _ in marker
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
        {
            relative_escape.push("..");
        }
        for c in registry.join("cargo").components() {
            if let std::path::Component::Normal(part) = c {
                relative_escape.push(part);
            }
        }
        std::os::unix::fs::symlink(&relative_escape, marker.join("cargo")).unwrap();

        let search_dirs = [marker.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_an_absolute_candidates_relative_symlink_escaping_system_mounts_as_setup_required()
     {
        // The initial-candidate `is_system_ro` check only proves the literal
        // configured path starts inside a mounted root; it says nothing about
        // where a *relative* symlink hop the walk then follows ends up. Needs
        // a real writable location under a SYSTEM_RO root (the check is a
        // literal path-prefix match, not mockable) — skipped, not failed,
        // wherever this process can't write there (an unprivileged CI runner),
        // the same environment-conditional shape already used above for the
        // real-/usr/bin/bash fixture.
        let probe_root = Path::new("/opt");
        let marker = probe_root.join(format!("ward-readiness-test-{}", std::process::id()));
        if std::fs::create_dir(&marker).is_err() {
            return; // no write access here; the mechanism is covered by the
            // project-relative and search-dir variants above either way.
        }
        let _cleanup = RemoveDirOnDrop(marker.clone());
        assert!(
            crate::sandbox::is_system_ro(&marker),
            "/opt is unconditionally in SYSTEM_RO"
        );

        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("tool"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&outside.path().join("tool"));
        // marker/tool -> a relative path out of `marker` (under the SYSTEM_RO
        // root) into `outside` (a plain /tmp tempdir, mounted nowhere): built
        // by counting marker's own components back to `/`, then descending
        // into outside's — never an absolute target, so only a
        // post-resolution containment check catches it.
        let mut relative_escape = PathBuf::new();
        for _ in marker
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
        {
            relative_escape.push("..");
        }
        for c in outside.path().join("tool").components() {
            if let std::path::Component::Normal(part) = c {
                relative_escape.push(part);
            }
        }
        std::os::unix::fs::symlink(&relative_escape, marker.join("tool")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            &format!("verify:\n  command: {}\n", marker.join("tool").display()),
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_ignores_a_program_that_exists_only_outside_the_verifiers_search_dirs() {
        // `ward verify` runs in a sandbox whose PATH is the verifier's own
        // (Toolchains::search_dirs), never the calling process's — a program
        // sitting anywhere else on disk (an NVM directory, a user-local bin, …)
        // is invisible to the verifier even though it genuinely exists and is
        // executable right here.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: mytool\n",
        );
        let caller_only = tempfile::tempdir().unwrap();
        let tool = caller_only.path().join("mytool");
        std::fs::write(&tool, "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&tool);

        // Not one of the verifier's search dirs: Fail, despite the program
        // existing and being executable right there.
        let report = check_with_dirs(dir.path(), &[]);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);

        // The very same directory, once it *is* a verifier search dir: Ok. The
        // only thing that changed is search_dirs, never the filesystem state.
        let dirs = [caller_only.path().to_path_buf()];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_finds_a_toolchain_style_bin_directory_nowhere_on_a_conventional_path() {
        // Mirrors verify::Toolchains::search_dirs()'s own shape: a mounted
        // Cargo `bin/` is checked directly, at whatever host path the toolchain
        // actually lives at — not /usr/bin, not /usr/local/bin, not anything a
        // caller's own PATH would conventionally contain — because that mounted
        // directory is genuinely what the verifier searches, regardless of the
        // calling process's own PATH.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let toolchain_home = tempfile::tempdir().unwrap();
        let bin = toolchain_home.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cargo_bin = bin.join("cargo");
        std::fs::write(&cargo_bin, "not a real binary").unwrap();
        make_executable(&cargo_bin);

        let dirs = [bin];
        let report = check_with_dirs(dir.path(), &dirs);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_resolves_a_project_relative_executable_against_the_project_not_path() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("scripts/verify.sh");
        write(dir.path(), "scripts/verify.sh", "#!/bin/sh\ntrue\n");
        make_executable(&script);
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);

        // The same relative path, absent, is a real Fail — not silently ignored.
        let missing = tempfile::tempdir().unwrap();
        write(
            missing.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify.sh\n",
        );
        let report = check(missing.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_present_but_non_executable_project_file_as_setup_required() {
        // A regular file with no execute bit exists at the path but `/bin/sh -c`
        // cannot start it (permission denied, exit 126) — this must not be Ok.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "scripts/verify.sh", "#!/bin/sh\ntrue\n");
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert!(row.detail.contains("not executable"), "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_directory_candidate_as_setup_required_not_ok() {
        // A directory commonly has every execute ("search") bit set — mode 0755,
        // same as std::fs::create_dir_all's default — which a coarse
        // `mode & 0o111 != 0` check would misread as "executable". It is not a
        // runnable program: `/bin/sh -c './scripts'` fails with exit 126.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("scripts")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_allows_a_project_relative_symlink_naming_the_work_mount() {
        // Review finding on #219 (head b4614ce, "absolute symlinks to known
        // non-identity sandbox mounts are falsely rejected"): the worktree
        // itself is bind-mounted at `/work` (sandbox.rs's `Launch::args`),
        // but `/work` names nothing on the host at all — a symlink naming it
        // is only ever meant to be followed *inside* the verifier. The host
        // link is intentionally broken (`/work` doesn't exist here), yet
        // `ward verify` resolves it through the real bind and runs it.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tools/verify.sh", "#!/bin/sh\ntrue\n");
        make_executable(&dir.path().join("tools/verify.sh"));
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::os::unix::fs::symlink("/work/tools/verify.sh", dir.path().join("bin/verify.sh"))
            .unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./bin/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_allows_a_cargo_bin_absolute_symlink_naming_the_registry_mount() {
        // The other reproduction from the same finding: an absolute symlink
        // naming a toolchain mount's own sandbox path
        // (`/run/verifier/cargo/registry/…`) is valid inside the verifier
        // even though nothing exists at that literal path on the host.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cargo test\n",
        );
        let cargo_home = tempfile::tempdir().unwrap();
        let bin = cargo_home.path().join("bin");
        let registry = cargo_home.path().join("registry");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(registry.join("cargo"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&registry.join("cargo"));
        std::os::unix::fs::symlink("/run/verifier/cargo/registry/cargo", bin.join("cargo"))
            .unwrap();

        let search_dirs = [bin.clone()];
        let mounts = cargo_mounts(bin, registry);
        let report = check_with_dirs_and_roots(dir.path(), &search_dirs, &mounts);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_an_absolute_path_outside_system_mounts_as_setup_required() {
        // /tmp is replaced with an empty, private tmpfs inside the verifier
        // sandbox (sandbox.rs's Launch::args); a real, executable file at an
        // absolute /tmp path on the host is still invisible inside it. tempdir()
        // itself lives under /tmp (or $TMPDIR), so this is exactly that case.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let tool = outside.path().join("ward-test-tool");
        std::fs::write(&tool, "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&tool);
        write(
            dir.path(),
            ".tamperward/config.yml",
            &format!("verify:\n  command: {}\n", tool.display()),
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_project_relative_absolute_symlink_as_setup_required() {
        // The verifier only ever binds the worktree itself into the sandbox (at
        // /work), never at the host's own temp-directory path — so an *absolute*
        // symlink target is broken inside it even when it points to somewhere
        // still nominally "under" the worktree on the host (dir.path() is itself
        // an absolute /tmp/... path; the sandbox does not mount /tmp at all,
        // let alone at that literal path). Only a *relative* internal symlink
        // (the next test) survives the sandbox relocating the worktree to /work.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("tools/verify.sh");
        write(dir.path(), "tools/verify.sh", "#!/bin/sh\ntrue\n");
        make_executable(&real);
        // An absolute target, even though it resolves under `dir` on this host.
        std::os::unix::fs::symlink(&real, dir.path().join("verify")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./verify\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_allows_a_project_relative_symlink_that_stays_within_the_worktree() {
        // A *relative* symlink target, resolved against its own containing
        // directory, is exactly what a bind mount of the worktree preserves
        // verbatim regardless of where it ends up mounted — so this one is Ok.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tools/verify.sh", "#!/bin/sh\ntrue\n");
        make_executable(&dir.path().join("tools/verify.sh"));
        std::os::unix::fs::symlink("tools/verify.sh", dir.path().join("verify")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./verify\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_project_relative_symlink_escaping_the_worktree_as_setup_required() {
        // Even a *relative* symlink chain can still net outside the worktree
        // through enough `..` components — still a real escape, still Fail,
        // independent of the absolute-target case above.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("ward-test-tool"), "#!/bin/sh\ntrue\n").unwrap();
        make_executable(&outside.path().join("ward-test-tool"));
        // dir/scripts/verify -> ../../<outside's basename>/ward-test-tool: two
        // levels up from dir/scripts reaches the common parent both tempdir()s
        // share (their base temp directory), then back down into `outside`.
        let relative_escape = PathBuf::from("../..")
            .join(outside.path().file_name().unwrap())
            .join("ward-test-tool");
        std::fs::create_dir_all(dir.path().join("scripts")).unwrap();
        std::os::unix::fs::symlink(&relative_escape, dir.path().join("scripts/verify")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_quoted_command_indeterminate_not_setup_required() {
        // Whitespace-splitting `"cargo" test` produces the literal token `"cargo"`
        // (quotes included), not the program name `cargo` a real shell would run;
        // this must not be probed on PATH as that literal string.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: '\"cargo\" test'\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Warn, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_compound_command_indeterminate_rather_than_probing_a_builtin() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cd subdir && cargo test\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        // Neither a false Ok nor a false Fail: `cd` is a shell builtin with no PATH
        // entry, and the command as a whole is a list (`&&`), not a single program.
        assert_eq!(row.status, Status::Warn, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_bare_assignment_indeterminate() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: FOO=bar\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Warn, "{}", row.detail);
    }

    #[test]
    fn a_pushed_row_participates_in_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let mut report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited); // empty protected.tests
        report.push(Row::new("credential", Status::Fail, "no key configured"));
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn ecosystem_detects_the_recognised_manifests() {
        for (file, eco, label) in [
            ("Cargo.toml", Ecosystem::Cargo, "cargo"),
            ("package.json", Ecosystem::Npm, "npm"),
            ("pyproject.toml", Ecosystem::Python, "python"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(file), "").unwrap();
            assert_eq!(Ecosystem::detect(dir.path()), eco);
            assert_eq!(eco.to_string(), label);
        }
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Ecosystem::detect(dir.path()), Ecosystem::Unknown);
    }

    #[test]
    fn verdict_blocks_only_setup_required_and_unavailable() {
        assert!(!Verdict::Ready.blocks());
        assert!(!Verdict::Limited.blocks());
        assert!(Verdict::SetupRequired.blocks());
        assert!(Verdict::Unavailable.blocks());
    }
}
