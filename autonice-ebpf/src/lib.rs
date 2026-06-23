#![no_std]

// Exists only to give this crate a lib target, so the userspace crate can
// depend on it for cache invalidation without a warning. The actual eBPF
// program lives in src/main.rs.
