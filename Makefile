# autonice — eBPF-driven automatic renicing.
# Run `make` (or `make help`) to list targets.

# Overridable knobs:
RUST_LOG ?= info
BIN      := target/debug/autonice
OBJ      := $(shell find target -path '*aya-build*/bpfel-unknown-none/release/autonice' 2>/dev/null | head -n1)

.DEFAULT_GOAL := help

.PHONY: help build release run check test fmt clippy ebpf-dump tracepoint-format deps clean docker

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the daemon + eBPF object (debug)
	cargo build

release: ## Build optimized release binaries
	cargo build --release

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

tracepoint-format: ## Show the sched_process_exec field layout (verifies hardcoded offsets)
	sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format

deps: ## Install build prerequisites (bpf-linker + nightly rust-src)
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker

clean: ## Remove build artifacts
	cargo clean

docker:
	docker compose up
