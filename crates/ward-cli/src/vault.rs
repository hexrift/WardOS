//! `ward vault`: the keys the host keeps for the proxy (ADR-0017, ADR-0008).
//!
//! One file per key under `$WARD_STATE_DIR/vault/`, named by the host variable the
//! gateway looks for (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`), mode
//! 0600 in a 0700 directory. The path is [`gateway::vault_file`], the same function
//! the gateway reads through, so `set` and the proxy can never disagree. A stored
//! value is never printed back: `list` says whether a key is set, and nothing more.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use ward_daemon::{Error, Result, gateway};

/// An I/O error with the path it happened at.
fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
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
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| io(&dir, e))?;
    // A directory that existed with looser permissions is tightened, not trusted.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(&dir, e))?;
    let path = gateway::vault_file(state, name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| io(&path, e))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| io(&path, e))?;
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
    #![allow(clippy::unwrap_used)]

    use super::*;

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
