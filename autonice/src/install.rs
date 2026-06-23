//! `autonice install` — self-install as a systemd service.
//!
//! Copies the running binary to /usr/local/bin, writes the systemd unit and a
//! default config (both baked in with `include_str!`), then enables the
//! service. Because the unit and config travel inside the binary, a single
//! `autonice` file is all you need on the target host — no repo checkout, no
//! separate files to copy. Mirrors the manual steps documented in the README.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, bail};

use crate::DEFAULT_CONFIG;

/// The systemd unit, baked in at compile time so the binary is self-installing.
const SERVICE: &str = include_str!("../../autonice.service");

const BIN_DEST: &str = "/usr/local/bin/autonice";
const UNIT_DEST: &str = "/etc/systemd/system/autonice.service";
const CONFIG_DEST: &str = "/etc/autonice.toml";
const SERVICE_NAME: &str = "autonice";

pub fn run() -> anyhow::Result<()> {
    // Writing to /usr/local/bin + /etc and driving systemd all need root.
    // SAFETY: geteuid is a side-effect-free syscall.
    if unsafe { libc::geteuid() } != 0 {
        bail!("`autonice install` must run as root (try: sudo autonice install)");
    }

    install_self()?;
    write_file(UNIT_DEST, SERVICE.as_bytes(), 0o644)?;
    println!("wrote {UNIT_DEST}");
    install_config()?;

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", SERVICE_NAME])?;

    println!(
        "\nautonice is installed and running.\n  \
         status: systemctl status {SERVICE_NAME}\n  \
         logs:   journalctl -u {SERVICE_NAME} -f"
    );
    Ok(())
}

/// Copy the running binary to BIN_DEST (unless we're already running from it —
/// copying a file onto itself truncates it).
fn install_self() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("locate the running executable")?;
    let dest = Path::new(BIN_DEST);
    let already_installed = matches!(
        (exe.canonicalize(), dest.canonicalize()),
        (Ok(a), Ok(b)) if a == b
    );
    if already_installed {
        println!("{BIN_DEST} is already the running binary; leaving it in place");
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::copy(&exe, dest).with_context(|| format!("install binary to {BIN_DEST}"))?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {BIN_DEST}"))?;
    println!("installed {} -> {BIN_DEST}", exe.display());
    Ok(())
}

/// Write the default config, but never clobber one the user already has.
fn install_config() -> anyhow::Result<()> {
    if Path::new(CONFIG_DEST).exists() {
        println!("{CONFIG_DEST} already exists; keeping it");
        return Ok(());
    }
    write_file(CONFIG_DEST, DEFAULT_CONFIG.as_bytes(), 0o644)?;
    println!("wrote default config {CONFIG_DEST}");
    Ok(())
}

fn write_file(path: &str, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("write {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {path}"))?;
    Ok(())
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .context("run systemctl (is this a systemd host?)")?;
    if !status.success() {
        bail!("systemctl {} failed ({status})", args.join(" "));
    }
    Ok(())
}
