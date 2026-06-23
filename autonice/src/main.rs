//! autonice — automatically renice processes at exec time.
//!
//! An eBPF tracepoint on `sched_process_exec` streams every exec to userspace
//! over a ring buffer; we match each exec against a config file and call
//! `setpriority(2)` to set its nice value. eBPF detects, userspace acts.
//!
//! Two kinds of matching:
//!   * single-binary rules ([rules]) — match by basename or path substring;
//!   * cargo subtree ([cargo]) — renice `cargo` AND everything it spawns
//!     transitively (rustc, build scripts, cc, ld), tracked by parent pid.

mod install;

use std::collections::{HashMap, HashSet};
use std::mem;

use anyhow::Context as _;
use autonice_common::ExecEvent;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::{debug, info, warn};
use serde::Deserialize;
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{SignalKind, signal};

/// How many events between sweeps that drop dead pids from the subtree set.
const PRUNE_INTERVAL: u32 = 500;

#[derive(Debug, Deserialize, Default)]
struct Config {
    /// match-key -> rule. A key matches a binary's basename; a rule can opt in
    /// to also matching any substring of the full exec path with
    /// `substring = true`.
    #[serde(default)]
    rules: HashMap<String, Rule>,
    /// If present, renice `cargo` and its entire process subtree to this nice.
    #[serde(default)]
    cargo: Option<CargoConfig>,
}

/// A `[rules]` value, in either shorthand or table form:
///   dd = 19                               # basename only
///   dd = { nice = 19, substring = true }  # also match any path substring
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Rule {
    Nice(i32),
    Table {
        nice: i32,
        /// Also match any substring of the full exec path, not just the
        /// basename. Off by default (so e.g. `dd` won't match `ssh-add`).
        #[serde(default)]
        substring: bool,
    },
}

impl Rule {
    fn nice(&self) -> i32 {
        match self {
            Rule::Nice(n) => *n,
            Rule::Table { nice, .. } => *nice,
        }
    }

    /// Whether this rule may also match a path substring (not just the basename).
    fn substring(&self) -> bool {
        matches!(
            self,
            Rule::Table {
                substring: true,
                ..
            }
        )
    }
}

#[derive(Debug, Deserialize)]
struct CargoConfig {
    nice: i32,
}

impl Config {
    /// First matching rule wins: an exact basename match (any rule form), then a
    /// path-substring match (only rules that opt in with `substring = true`).
    fn nice_for(&self, path: &str) -> Option<i32> {
        let basename = basename(path);
        if let Some(rule) = self.rules.get(basename) {
            return Some(rule.nice());
        }
        self.rules
            .iter()
            .find(|(k, rule)| rule.substring() && path.contains(k.as_str()))
            .map(|(_, rule)| rule.nice())
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The starter config, baked into the binary. Used three ways: written by
/// `autonice install`, printed by `autonice default`, and parsed as the runtime
/// fallback when no config file is found on disk.
pub(crate) const DEFAULT_CONFIG: &str = include_str!("../../autonice.toml");

fn load_config() -> Config {
    for path in ["autonice.toml", "/etc/autonice.toml"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            match toml::from_str::<Config>(&text) {
                Ok(cfg) => {
                    info!(
                        "loaded {} rule(s){} from {path}",
                        cfg.rules.len(),
                        if cfg.cargo.is_some() {
                            " + cargo-subtree tracking"
                        } else {
                            ""
                        },
                    );
                    return cfg;
                }
                Err(e) => warn!("failed to parse {path}: {e}"),
            }
        }
    }
    // No config file on disk — fall back to the built-in default so a fresh
    // install acts sensibly out of the box (`autonice default` prints it).
    info!("no config file found; using built-in defaults (see `autonice default`)");
    toml::from_str(DEFAULT_CONFIG).expect("embedded default config must parse")
}

/// Parent pid of `pid` from /proc/<pid>/stat. The `comm` field can contain
/// spaces and parens, so we parse everything after the final ')'.
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // fields after comm: " <state> <ppid> ..."
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// Set the nice value of `pid`. Lowering nice (raising priority) or reniceing a
/// process we don't own requires CAP_SYS_NICE.
fn renice(pid: u32, nice: i32) -> std::io::Result<()> {
    // SAFETY: plain syscall with scalar args.
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Runtime state carried across events.
struct Daemon {
    config: Config,
    /// pids known to be `cargo` or a descendant of one.
    cargo_subtree: HashSet<u32>,
    events_since_prune: u32,
}

impl Daemon {
    fn new(config: Config) -> Self {
        Self {
            config,
            cargo_subtree: HashSet::new(),
            events_since_prune: 0,
        }
    }

    fn apply(&self, pid: u32, nice: i32, path: &str, why: &str) {
        match renice(pid, nice) {
            Ok(()) => info!("renice pid={pid} nice={nice} [{why}] {path}"),
            Err(e) => warn!("renice pid={pid} nice={nice} [{why}] {path} failed: {e}"),
        }
    }

    fn handle(&mut self, bytes: &[u8]) {
        if bytes.len() < mem::size_of::<ExecEvent>() {
            return;
        }
        // SAFETY: ExecEvent is `#[repr(C)]` Pod; length checked. Unaligned read
        // since the ring buffer slice has no alignment guarantee.
        let event: ExecEvent = unsafe { (bytes.as_ptr() as *const ExecEvent).read_unaligned() };

        let len = (event.filename_len as usize).min(event.filename.len());
        let path = String::from_utf8_lossy(&event.filename[..len]);
        let path = path.trim_end_matches('\0');
        let pid = event.pid;

        // --- cargo subtree: cargo itself, or any child of a tracked pid ---
        if let Some(cargo) = &self.config.cargo {
            let in_subtree = basename(path) == "cargo"
                || parent_pid(pid).is_some_and(|ppid| self.cargo_subtree.contains(&ppid));
            if in_subtree {
                self.cargo_subtree.insert(pid);
                self.apply(pid, cargo.nice, path, "cargo");
                self.prune_tick();
                return;
            }
            self.prune_tick();
        }

        // --- single-binary rules ---
        if let Some(nice) = self.config.nice_for(path) {
            self.apply(pid, nice, path, "rule");
        } else {
            debug!("exec pid={pid} {path} (no match)");
        }
    }

    /// Periodically drop pids whose process has exited, so the set stays bounded
    /// across many builds.
    fn prune_tick(&mut self) {
        self.events_since_prune += 1;
        if self.events_since_prune < PRUNE_INTERVAL {
            return;
        }
        self.events_since_prune = 0;
        let before = self.cargo_subtree.len();
        self.cargo_subtree
            .retain(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
        debug!(
            "pruned cargo subtree: {} -> {}",
            before,
            self.cargo_subtree.len()
        );
    }
}

fn print_usage() {
    eprintln!(
        "autonice — eBPF-driven automatic renicing\n\
         \n\
         Usage:\n  \
         autonice            Run the daemon (default).\n  \
         autonice install    Install + enable the systemd service (needs root).\n  \
         autonice default    Print the built-in default config to stdout.\n  \
         autonice help       Show this help."
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Subcommand dispatch before any daemon setup. `install` does plain sync
    // filesystem + systemctl work; everything else (or no arg) runs the daemon.
    match std::env::args().nth(1).as_deref() {
        Some("install") => return install::run(),
        Some("default") => {
            // Trailing newline comes from the embedded file; don't add another.
            print!("{DEFAULT_CONFIG}");
            return Ok(());
        }
        Some("help" | "-h" | "--help") => {
            print_usage();
            return Ok(());
        }
        None | Some("run") => {}
        Some(other) => {
            eprintln!("autonice: unknown subcommand `{other}`\n");
            print_usage();
            std::process::exit(2);
        }
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut daemon = Daemon::new(load_config());

    // Bump memlock rlimit for older kernels lacking memcg-based BPF accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: writing a well-formed rlimit.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("could not remove memlock rlimit (ret={ret}); continuing");
    }

    // Load the eBPF object embedded at compile time by build.rs.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/autonice"
    )))?;

    let program: &mut TracePoint = ebpf
        .program_mut("autonice")
        .context("program `autonice` not found")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;
    info!("attached to sched:sched_process_exec; watching execs…");

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;
    let mut async_fd = AsyncFd::new(ring)?;

    // Shut down on SIGINT (Ctrl-C) or SIGTERM — the latter is what `systemctl
    // stop` and `docker stop`/`compose down` send. The kernel auto-detaches the
    // BPF program when we exit; this just lets us log a clean shutdown.
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!("received SIGINT, shutting down");
                return Ok(());
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                return Ok(());
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    daemon.handle(item.as_ref());
                }
                guard.clear_ready();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded default must parse — `load_config` unwraps it, and
    /// `autonice install`/`default` ship it verbatim.
    #[test]
    fn embedded_default_config_parses() {
        let cfg: Config = toml::from_str(DEFAULT_CONFIG).expect("default config parses");
        assert!(cfg.cargo.is_some(), "default ships cargo-subtree tracking");
        assert!(!cfg.rules.is_empty(), "default ships some rules");
    }

    #[test]
    fn shorthand_rule_matches_basename_only() {
        let cfg: Config = toml::from_str("[rules]\ndd = 19\n").unwrap();
        assert_eq!(cfg.nice_for("/usr/bin/dd"), Some(19)); // exact basename
        assert_eq!(cfg.nice_for("/usr/bin/ssh-add"), None); // no substring by default
    }

    #[test]
    fn substring_rule_matches_path() {
        let cfg: Config =
            toml::from_str("[rules]\ndd = { nice = 19, substring = true }\n").unwrap();
        assert_eq!(cfg.nice_for("/usr/bin/dd"), Some(19)); // exact basename
        assert_eq!(cfg.nice_for("/usr/bin/ssh-add"), Some(19)); // opted-in substring
    }
}
