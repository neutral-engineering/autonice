# autonice — eBPF-driven automatic renicing.
# Run `make` (or `make help`) to list targets.

# Overridable knobs:
RUST_LOG ?= info
BIN      := target/debug/autonice
# Portable distribution build: a fully static musl binary has no glibc
# dependency, so one artifact runs on any Linux distro (Arch, Debian, …).
MUSL       := x86_64-unknown-linux-musl
STATIC_BIN := target/$(MUSL)/debug/autonice
OBJ      := $(shell find target -path '*aya-build*/bpfel-unknown-none/release/autonice' 2>/dev/null | head -n1)

.DEFAULT_GOAL := help

.PHONY: help build build-static release run check test fmt clippy ebpf-dump tracepoint-format deps clean docker docker-arch docker-debian

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the daemon + eBPF object (debug, native)
	cargo build

build-static: ## Build the static musl binary (debug) — used by the docker harness
	cargo build --target $(MUSL)
	@echo "built $(STATIC_BIN) (static; the docker harness mounts this)"

release: ## Build the portable static (musl) release binary — runs on any distro
	cargo build --release --target $(MUSL)
	@echo "built target/$(MUSL)/release/autonice (static; runs on Arch, Debian, …)"

run: build ## Run the daemon as root (override: make run RUST_LOG=debug)
	sudo RUST_LOG=$(RUST_LOG) $(BIN)

check: ## Type-check the whole workspace without producing binaries
	cargo check

test: ## Run the test suite
	cargo test

fmt: ## Format all crates
	cargo fmt --all

clippy: ## Lint with clippy (warnings as errors)
	cargo clippy --all-targets -- -D warnings

ebpf-dump: build ## Inspect the generated eBPF ELF (sections + program disasm)
	@echo "Object: $(OBJ)"
	llvm-readelf -S "$(OBJ)"
	llvm-objdump -d "$(OBJ)"

tracepoint-format: ## Show the sched_process_{exec,fork} field layouts (verifies hardcoded offsets)
	sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
	sudo cat /sys/kernel/tracing/events/sched/sched_process_fork/format

deps: ## Install build prerequisites (bpf-linker + nightly rust-src + musl target)
	rustup component add rust-src --toolchain nightly
	rustup target add $(MUSL)
	cargo install bpf-linker

clean: ## Remove build artifacts
	cargo clean

docker: docker-debian ## Run the local test harness on Debian (alias for docker-debian)

docker-arch: build-static ## Run the host-built static binary in an Arch container
	docker compose --profile arch up

docker-debian: build-static ## Run the host-built static binary in a Debian container
	docker compose --profile debian up
