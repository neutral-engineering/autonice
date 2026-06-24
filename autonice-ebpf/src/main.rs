#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use autonice_common::{ExecEvent, ForkEvent};

/// Ring buffer that carries exec events to userspace. 256 KiB is plenty for a
/// bursty-but-low-rate event like process exec.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Ring buffer that carries fork events to userspace. Forks are higher-rate than
/// execs but each event is tiny (8 bytes), so the same 256 KiB holds far more.
#[map]
static FORKS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Field offsets within the `sched/sched_process_exec` tracepoint record. These
// come from /sys/kernel/tracing/events/sched/sched_process_exec/format and have
// been stable for many kernel releases:
//
//   field:__data_loc char[] filename;  offset:8;   size:4;
//   field:pid_t pid;                   offset:12;  size:4;
//
// Verify on a given kernel with:
//   sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format
const FILENAME_DATA_LOC_OFFSET: usize = 8;
const PID_OFFSET: usize = 12;

// Field offsets within the `sched/sched_process_fork` tracepoint record. From
// /sys/kernel/tracing/events/sched/sched_process_fork/format; stable for many
// kernel releases (the layout is fixed by the kernel's TRACE_EVENT macro):
//
//   field:char  parent_comm[16];  offset:8;   size:16;
//   field:pid_t parent_pid;       offset:24;  size:4;
//   field:char  child_comm[16];   offset:28;  size:16;
//   field:pid_t child_pid;        offset:44;  size:4;
//
// Verify on a given kernel with:
//   sudo cat /sys/kernel/tracing/events/sched/sched_process_fork/format
const PARENT_PID_OFFSET: usize = 24;
const CHILD_PID_OFFSET: usize = 44;

#[tracepoint]
pub fn autonice(ctx: TracePointContext) -> u32 {
    match try_autonice(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_autonice(ctx: TracePointContext) -> Result<u32, i64> {
    // Read the fixed fields *before* reserving so an early error can't leak an
    // unsubmitted ring-buffer reservation.
    //
    // A `__data_loc` field packs (length << 16) | offset, both relative to the
    // start of the tracepoint record (i.e. `ctx.as_ptr()`).
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_DATA_LOC_OFFSET)? };
    let pid: u32 = unsafe { ctx.read_at(PID_OFFSET)? };
    let filename_offset = (data_loc & 0xFFFF) as usize;

    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        // Ring buffer full: drop this event rather than block the exec path.
        return Ok(0);
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = pid;
        (*event).filename_len = 0;

        let src = ctx.as_ptr().add(filename_offset) as *const u8;
        if let Ok(read) = bpf_probe_read_kernel_str_bytes(src, &mut (*event).filename) {
            (*event).filename_len = read.len() as u32;
        }
    }
    entry.submit(0);

    Ok(0)
}

#[tracepoint]
pub fn autonice_fork(ctx: TracePointContext) -> u32 {
    match try_fork(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_fork(ctx: TracePointContext) -> Result<u32, i64> {
    // Two fixed u32 reads — no `__data_loc` string to unpack, so simpler than the
    // exec path.
    let parent_pid: u32 = unsafe { ctx.read_at(PARENT_PID_OFFSET)? };
    let child_pid: u32 = unsafe { ctx.read_at(CHILD_PID_OFFSET)? };

    let Some(mut entry) = FORKS.reserve::<ForkEvent>(0) else {
        // Ring buffer full: drop this event rather than block the fork path.
        return Ok(0);
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).parent_pid = parent_pid;
        (*event).child_pid = child_pid;
    }
    entry.submit(0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
