# autonice

Automatically renice processes the moment they exec, driven by eBPF.

A tracepoint on `sched_process_exec` streams every exec to a userspace daemon,
which matches the binary against a config and calls `setpriority(2)`.
**eBPF detects, userspace acts** — there's no BPF helper to renice a task, so the
kernel side only reports execs and the daemon does the reniceing.

## How it works

```
 kernel                          userspace (tokio)
 ┌──────────────────────┐        ┌────────────────────────────┐
 │ sched_process_exec   │  ring  │ match path against config  │
 │  → pid + exec path   │ ─────► │  → setpriority(pid, nice)  │
 └──────────────────────┘  buf   └────────────────────────────┘
```

Two kinds of match:

- **Single binaries** (`[rules]`) — by basename; opt in to path-substring
  matching with the table form `{ nice = N, substring = true }`.
- **`cargo` subtree** (`[cargo]`) — renice `cargo` *and everything it spawns*
  (rustc, build scripts, `cc`, `ld`), tracked by parent pid so standalone
  `rustc`/`cc` outside cargo are left alone.

## Requirements

- Linux with BTF (`/sys/kernel/tracing`, kernel 5.8+).
- Rust nightly with `rust-src` + [`bpf-linker`] (for building the eBPF crate).
- Root (or `CAP_BPF`+`CAP_PERFMON` to load BPF, `CAP_SYS_NICE` to renice others /
  set negative nice).

```sh
make deps   # rustup component add rust-src --toolchain nightly && cargo install bpf-linker
```

## Build & run

```sh
make build                       # or: cargo build
sudo RUST_LOG=info ./target/debug/autonice
# or:  make run                  # wraps the binary in `sudo -E`
```

`make` on its own lists every target.

### Quick test in a container

[`docker-compose.yml`](docker-compose.yml) runs the host-built binary in a thin
container to watch it act on the host's execs:

```sh
make build && docker compose up
```

It builds nothing (the image just runs the binary, which already embeds the eBPF
object). It needs `privileged` and — critically — `pid: host`, because the eBPF
reports global pids that `setpriority`/`/proc` only resolve in the host pid
namespace. That makes it barely isolated from the host: a convenience harness,
not a sandbox. See the file's header for the full rationale.

## Configuration

Read from `./autonice.toml` then `/etc/autonice.toml`. Nice ranges from `-20`
(highest priority) to `19` (lowest). If no config exists, uses internal default.

```toml
[cargo]
nice = 19          # cargo + its whole build subtree

[rules]
dd = 19                                 # <basename> = <nice>; matches basename only
ffmpeg = { nice = 15, substring = true } # also matches any path substring
make = 10
# pipewire = -10                        # negative nice needs CAP_SYS_NICE
```

## Layout

| Crate              | Role                                                          |
| ------------------ | ------------------------------------------------------------ |
| `autonice-ebpf`    | eBPF program: tracepoint → ring buffer (`#![no_std]`)        |
| `autonice-common`  | `ExecEvent` shared kernel ↔ userspace                        |
| `autonice`         | daemon: drain ring buffer, match config, `setpriority`       |

Built with [Aya]. The userspace `build.rs` compiles the eBPF crate via
`aya-build` (cargo-in-cargo with `-Z build-std`) and embeds the object.

## Running as a service

Instead of full root, run it with just the capabilities it needs (see
[`autonice.service`](autonice.service)). The binary self-installs: the unit file
and a default config are baked in (`include_str!`), so `autonice install` copies
the running binary to `/usr/local/bin`, writes the unit + `/etc/autonice.toml`
(kept if it already exists), and enables the service:

```sh
make release
sudo ./target/release/autonice install
journalctl -u autonice -f
```

Equivalently, by hand:

```sh
sudo install -Dm755 target/release/autonice /usr/local/bin/autonice
sudo install -Dm644 autonice.toml            /etc/autonice.toml
sudo install -Dm644 autonice.service          /etc/systemd/system/autonice.service
sudo systemctl daemon-reload && sudo systemctl enable --now autonice
```

## Setup notes

- **Pinned for reproducibility.** The `aya` deps are git (no `rev`), so the
  committed `Cargo.lock` is what pins them — keep it committed.
  `rust-toolchain.toml` pins the nightly + `rust-src`, since the eBPF crate's
  `-Z build-std` is sensitive to the exact nightly.
- **`rust-src` must be *installed*, not just available** —
  `rustup component add rust-src --toolchain nightly` (in `make deps`).
- **`AYA_BUILD_SKIP=1`** skips the eBPF rebuild when iterating on userspace only.
- **Userspace builds on stable**; only the eBPF crate needs nightly, and
  `aya-build` invokes it via `rustup run nightly` — no need to switch defaults.
- **Introspect a running daemon** with `bpftool prog show` and
  `bpftool map dump name EVENTS`.
- Verifier errors only appear on a *privileged* load; use `RUST_LOG=debug` for
  aya's verifier log.

## Caveats

- Parent pid for subtree tracking comes from `/proc/<pid>/stat`, which has a tiny
  race: a sub-millisecond child can exit before it's read. Hooking
  `sched_process_fork` would make ancestry race-free.
- Tracepoint field offsets (`filename` @ 8, `pid` @ 12) are hardcoded; verify on
  your kernel with `make tracepoint-format`.

## License

GPL2.0

[Aya]: https://aya-rs.dev
[`bpf-linker`]: https://github.com/aya-rs/bpf-linker
