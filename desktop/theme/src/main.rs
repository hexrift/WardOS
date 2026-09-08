//! `wardos-theme-render` — writes a theme's fragments into a directory.
//!
//! ```text
//! wardos-theme-render <id-or-path> --out <dir>
//! ```
//!
//! The id is searched in `$WARDOS_THEMES`, `~/.local/share/wardos/themes`,
//! `/usr/share/wardos/themes` and `$WARDOS_ROOT/themes`; a path is taken as
//! given. Fonts: the theme's, unless `~/.config/wardos/fonts.conf`
//! (`sans=`, `mono=`) or `WARDOS_FONT_SANS`/`WARDOS_FONT_MONO` say otherwise.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use wardos_theme::{Error, Fonts, Overrides, Theme, locate, render_into, search_dirs};

#[derive(Parser)]
#[command(
    name = "wardos-theme-render",
    version,
    about = "Render a WardOS theme into every component's format"
)]
struct Cli {
    /// Theme id (`ward-dark`) or path to a theme TOML.
    theme: String,
    /// Directory to write the fragments into (created if needed).
    #[arg(long)]
    out: PathBuf,
}

fn fonts_conf() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|c| c.join("wardos/fonts.conf"))
}

fn run(cli: &Cli) -> Result<(), Error> {
    let found = locate(&cli.theme, &search_dirs())?;
    let theme = Theme::parse(&std::fs::read_to_string(&found.path)?)?;
    let from_file = fonts_conf()
        .map(|p| Overrides::from_file(&p))
        .unwrap_or_default();
    let fonts = Fonts::resolve(&theme, &Overrides::from_env().over(from_file));
    render_into(&theme, Some(&found.backgrounds), &fonts, &cli.out)?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wardos-theme-render: {e}");
            ExitCode::FAILURE
        }
    }
}
