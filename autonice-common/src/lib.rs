#![no_std]

/// Max bytes we capture for an exec'd binary's path (NUL-terminated, truncated).
pub const FILENAME_LEN: usize = 256;

/// One process-exec event, shared verbatim between the eBPF program (producer)
/// and the userspace daemon (consumer) via the ring buffer.
///
/// `#[repr(C)]` with the two `u32`s first keeps the layout padding-free
/// (4 + 4 + 256 = 264 bytes, align 4), which is required for `aya::Pod`.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ExecEvent {
    /// PID (tgid) of the process that just exec'd.
    pub pid: u32,
    /// Number of valid bytes in `filename` (excludes the trailing NUL).
    pub filename_len: u32,
    /// Absolute path of the exec'd binary, NUL-terminated, truncated to fit.
    pub filename: [u8; FILENAME_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
