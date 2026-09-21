//! `ward vault`: the keys the host keeps for the proxy (ADR-0017, ADR-0008).
//!
//! One file per key under `$WARD_STATE_DIR/vault/`, named by the host variable the
//! gateway looks for (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`), mode
//! 0600 in a 0700 directory. The path is [`gateway::vault_file`], the same function
//! the gateway reads through, so `set` and the proxy can never disagree. A stored
//! value is never printed back: `list` says whether a key is set, and nothing more.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use ward_daemon::{Error, Result, gateway};

/// An I/O error with the path it happened at.
fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

/// Open `dir` as a verified, non-symlink real directory, creating it (mode `0o700`)
/// first if it is absent — its own parent must already exist. Returns a directory fd
/// so the caller can create the vault entry beneath *that exact directory instance*
/// via `openat`: an fd-relative open resolves against the fd's inode, not whatever
/// name currently points there, so it stays correct even if `dir` is renamed away and
/// replaced with a symlink immediately after this call returns — a plain
/// check-then-reopen-by-path could not close that window.
///
/// `O_NOFOLLOW` alone (no `O_DIRECTORY`) is deliberate: combined, Linux reports a
/// symlink-to-a-directory as `ENOTDIR` — the `O_DIRECTORY` check runs first and a
/// symlink is never a directory type — indistinguishable from a plain non-directory
/// file. Checked apart, a symlink is reliably `ELOOP`, and a non-directory file is
/// caught by the explicit `is_dir` check below.
fn open_real_dir(dir: &Path, mode: u32) -> Result<rustix::fd::OwnedFd> {
    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(dir, e)),
    }
    let fd = rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            Error::Project(format!(
                "{}: refusing to use a symlink as a directory",
                dir.display()
            ))
        } else {
            io(dir, e.into())
        }
    })?;
    let st = rustix::fs::fstat(&fd).map_err(|e| io(dir, e.into()))?;
    if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() {
        return Err(Error::Project(format!(
            "{}: refusing to use a non-directory as the vault directory",
            dir.display()
        )));
    }
    // A directory that existed with looser permissions is tightened, not trusted —
    // now that it is confirmed real, through the fd (fchmod) rather than the path.
    rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(mode))
        .map_err(|e| io(dir, e.into()))?;
    Ok(fd)
}

/// The keys the proxy knows how to inject, listed first by `list` even when unset.
pub const KNOWN: [&str; 3] = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"];

/// A name is a host variable: `[A-Z][A-Z0-9_]*`. Anything else (a path, a lower-case
/// word, an empty string) is refused before it can name a file.
pub fn validate(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(Error::Project(format!(
            "vault names are host variables, like ANTHROPIC_API_KEY ([A-Z][A-Z0-9_]*), not {name:?}"
        )))
    }
}

/// Where the vault is.
#[must_use]
pub fn dir(state: &Path) -> PathBuf {
    gateway::vault_dir(state)
}

/// Store `value` as `name`: the directory 0700, the file 0600, a trailing newline as
/// the gateway trims one. An empty value is refused, since the gateway would treat
/// the key as absent and the user would think it set.
pub fn set(state: &Path, name: &str, value: &str) -> Result<PathBuf> {
    validate(name)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Project(format!(
            "{name}: an empty value is not stored"
        )));
    }
    let dir = dir(state);
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    let dir_fd = open_real_dir(&dir, 0o700)?;
    let path = gateway::vault_file(state, name);
    // A vault entry is expected to sometimes already exist as a real file (re-running
    // `set` updates it), so unlike `ward init`'s templates this can't refuse every
    // pre-existing node — only a symlink. Creating it beneath the already-verified
    // directory fd (`openat`, not a second pathname lookup) with `O_NOFOLLOW` makes
    // this one call the entire decision: a name an attacker planted ahead of the
    // user's first `set` makes it fail with `ELOOP` instead of following it into
    // whatever the link points at, and nothing between validating `dir` and this call
    // can redirect where the entry actually lands.
    let file_fd = match rustix::fs::openat(
        &dir_fd,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::TRUNC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::LOOP => {
            return Err(Error::Project(format!(
                "{}: refusing to write through a symlink",
                path.display()
            )));
        }
        Err(e) => return Err(io(&path, e.into())),
    };
    // Permissions go through the already-open fd (fchmod), not the path again, so a
    // node swapped in after the open above can't be the one that gets chmod'd 0600.
    rustix::fs::fchmod(&file_fd, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(|e| io(&path, e.into()))?;
    let mut file: std::fs::File = file_fd.into();
    writeln!(file, "{value}").map_err(|e| io(&path, e))?;
    Ok(path)
}

/// Remove `name`; `false` when it was not set (not an error: the outcome is the same).
pub fn remove(state: &Path, name: &str) -> Result<bool> {
    validate(name)?;
    let path = gateway::vault_file(state, name);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(&path, e)),
    }
}

/// Where a key comes from, as `list` reports it. The gateway prefers the host
/// environment over the vault, so both are named when both hold a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Not set anywhere.
    Unset,
    /// A non-empty vault file.
    Vault,
    /// A non-empty host variable.
    Environment,
    /// Both; the environment wins.
    Both,
}

impl Source {
    /// The word `list` prints.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Unset => "not set",
            Self::Vault => "set · vault",
            Self::Environment => "set · environment",
            Self::Both => "set · environment (vault too)",
        }
    }
}

/// Every known key and every file in the vault, with where each is set. `env`
/// answers whether a host variable holds a non-empty value, so tests need not touch
/// the process environment.
pub fn list(state: &Path, env: impl Fn(&str) -> bool) -> Result<Vec<(String, Source)>> {
    let mut names: Vec<String> = KNOWN.iter().map(|&n| n.to_owned()).collect();
    match std::fs::read_dir(dir(state)) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|e| io(dir(state), e))?;
                if let Some(name) = entry.file_name().to_str()
                    && validate(name).is_ok()
                    && !names.iter().any(|n| n == name)
                {
                    names.push(name.to_owned());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(dir(state), e)),
    }
    Ok(names
        .into_iter()
        .map(|name| {
            let in_vault = std::fs::read_to_string(gateway::vault_file(state, &name))
                .is_ok_and(|v| !v.trim().is_empty());
            let source = match (env(&name), in_vault) {
                (true, true) => Source::Both,
                (true, false) => Source::Environment,
                (false, true) => Source::Vault,
                (false, false) => Source::Unset,
            };
            (name, source)
        })
        .collect())
}

/// The value for `set`: the first line of stdin when asked (`--stdin`) or when
/// stdin is not a terminal, else typed at the terminal without echo.
pub fn read_value(name: &str, from_stdin: bool) -> Result<String> {
    let stdin = std::io::stdin();
    if from_stdin || !stdin.is_terminal() {
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| io("<stdin>", e))?;
        return Ok(line);
    }
    read_secret(&format!("{name} (not shown): "))
}

/// Read a line at the terminal with echo off: raw mode, one key at a time, until
/// Enter. Backspace edits; Ctrl-C or Ctrl-D cancels. Raw mode is restored on every
/// path out, including a panic, by the guard.
fn read_secret(prompt: &str) -> Result<String> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal;

    struct Cooked;
    impl Drop for Cooked {
        fn drop(&mut self) {
            let _ = terminal::disable_raw_mode();
            eprintln!();
        }
    }

    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    terminal::enable_raw_mode().map_err(|e| io("<tty>", e))?;
    let _cooked = Cooked;
    let mut value = String::new();
    loop {
        match crossterm::event::read().map_err(|e| io("<tty>", e))? {
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Enter => return Ok(value),
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(Error::Project("cancelled; nothing stored".to_owned()));
                }
                KeyCode::Char(c) => value.push(c),
                _ => {}
            },
            Event::Paste(text) => value.push_str(&text),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn names_are_host_variables() {
        for ok in ["ANTHROPIC_API_KEY", "A", "X_1"] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in ["", "anthropic", "1KEY", "../etc", "A-B", "A B", "_A"] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn set_writes_the_gateway_path_with_tight_modes_and_a_newline() {
        let state = tempfile::tempdir().unwrap();
        let path = set(state.path(), "ANTHROPIC_API_KEY", "sk-test\n").unwrap();
        assert_eq!(path, state.path().join("vault/ANTHROPIC_API_KEY"));
        assert_eq!(path, gateway::vault_file(state.path(), "ANTHROPIC_API_KEY"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sk-test\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir(state.path())), 0o700);
        // Replacing a value keeps the modes even when someone loosened them.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(dir(state.path()), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        set(state.path(), "ANTHROPIC_API_KEY", "sk-two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sk-two\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir(state.path())), 0o700);
    }

    #[test]
    fn refuses_to_write_the_secret_through_a_pre_planted_symlink() {
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("clobbered");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir(state.path()))
            .unwrap();
        std::os::unix::fs::symlink(&target, gateway::vault_file(state.path(), "GITHUB_TOKEN"))
            .unwrap();

        let Err(err) = set(state.path(), "GITHUB_TOKEN", "ghp-secret") else {
            panic!("expected the planted symlink to be refused");
        };
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(
            !target.exists(),
            "the secret must never reach the link's target"
        );

        // A real, previously-stored value is still replaced in place (no symlink).
        std::fs::remove_file(gateway::vault_file(state.path(), "GITHUB_TOKEN")).unwrap();
        set(state.path(), "GITHUB_TOKEN", "ghp-first").unwrap();
        set(state.path(), "GITHUB_TOKEN", "ghp-second").unwrap();
        assert_eq!(
            std::fs::read_to_string(gateway::vault_file(state.path(), "GITHUB_TOKEN")).unwrap(),
            "ghp-second\n"
        );
    }

    #[test]
    fn refuses_to_use_a_symlinked_vault_directory() {
        // `$WARD_STATE_DIR/vault` itself as a symlink to a real, existing directory
        // (e.g. a shared or reused state dir) is a deterministic hijack: with no
        // `GITHUB_TOKEN` file inside it yet, `DirBuilder::create`'s `AlreadyExists`
        // recovery must not treat "a symlink to a real directory" as "already there".
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir(state.path())).unwrap();

        let Err(err) = set(state.path(), "GITHUB_TOKEN", "ghp-secret") else {
            panic!("expected the symlinked vault directory to be refused");
        };
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(
            !outside.path().join("GITHUB_TOKEN").exists(),
            "must never write into the symlink's target directory"
        );
    }

    #[test]
    fn empty_values_and_bad_names_are_refused() {
        let state = tempfile::tempdir().unwrap();
        assert!(set(state.path(), "ANTHROPIC_API_KEY", "  \n").is_err());
        assert!(set(state.path(), "bad name", "x").is_err());
        assert!(!dir(state.path()).join("bad name").exists());
        assert!(remove(state.path(), "bad name").is_err());
    }

    #[test]
    fn list_names_every_known_key_and_extra_files_never_values() {
        let state = tempfile::tempdir().unwrap();
        let rows = list(state.path(), |_| false).unwrap();
        assert_eq!(
            rows,
            KNOWN
                .iter()
                .map(|&n| (n.to_owned(), Source::Unset))
                .collect::<Vec<_>>()
        );
        set(state.path(), "OPENAI_API_KEY", "sk-secret-value").unwrap();
        set(state.path(), "MY_TOKEN", "t").unwrap();
        std::fs::write(dir(state.path()).join("junk.txt"), "x").unwrap();
        let rows = list(state.path(), |name| {
            name == "GITHUB_TOKEN" || name == "MY_TOKEN"
        })
        .unwrap();
        let text: Vec<String> = rows
            .iter()
            .map(|(n, s)| format!("{n} {}", s.text()))
            .collect();
        assert_eq!(
            text,
            [
                "ANTHROPIC_API_KEY not set",
                "OPENAI_API_KEY set · vault",
                "GITHUB_TOKEN set · environment",
                "MY_TOKEN set · environment (vault too)",
            ]
        );
        assert!(!text.join("\n").contains("sk-secret-value"));
    }

    #[test]
    fn remove_is_idempotent() {
        let state = tempfile::tempdir().unwrap();
        set(state.path(), "GITHUB_TOKEN", "ghp").unwrap();
        assert!(remove(state.path(), "GITHUB_TOKEN").unwrap());
        assert!(!remove(state.path(), "GITHUB_TOKEN").unwrap());
        assert!(!gateway::vault_file(state.path(), "GITHUB_TOKEN").exists());
    }
}
