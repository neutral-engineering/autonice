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

use std::collections::{HashMap, HashSet};
use std::mem;

use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use autonice_common::ExecEvent;
use log::{debug, info, warn};
use serde::Deserialize;
use tokio::io::unix::AsyncFd;
use tokio::signal;

/// How many events between sweeps that drop dead pids from the subtree set.
const PRUNE_INTERVAL: u32 = 500;

#[derive(Debug, Deserialize, Default)]
struct Config {
    /// match-key -> nice value. A key matches a binary's basename or, failing
    /// that, any substring of its full exec path.
    #[serde(default)]
    rules: HashMap<String, i32>,
    /// If present, renice `cargo` and its entire process subtree to this nice.
    #[serde(default)]
    cargo: Option<CargoConfig>,
}

#[derive(Debug, Deserialize)]
struct CargoConfig {
    nice: i32,
}

impl Config {
    /// First matching rule wins (basename equality preferred over substring).
    fn nice_for(&self, path: &str) -> Option<i32> {
        let basename = basename(path);
        if let Some(n) = self.rules.get(basename) {
            return Some(*n);
        }
        self.rules
            .iter()
            .find(|(k, _)| path.contains(k.as_str()))
            .map(|(_, n)| *n)
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

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
    warn!("no config found (autonice.toml / /etc/autonice.toml); no rules active");
    Config::default()
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let mut shutdown = Box::pin(signal::ctrl_c());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutting down");
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
