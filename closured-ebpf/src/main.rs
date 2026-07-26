#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    cty::{c_char, c_int},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};
use aya_log_ebpf::info;
use closured_common::{
    Action, CLASSIFICATIONS, Classification, ExecEvent, FLAG_TMPFS, FLAG_UNLINKED, STORE_HASH_LEN,
};
use vmlinux::{file, linux_binprm, path};

#[allow(improper_ctypes)]
unsafe extern "C" {
    fn bpf_path_d_path(path: *mut path, buf: *mut c_char, buf__sz: usize) -> c_int;
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Store-path hash components of the allowed closure, populated by userspace.
#[map]
static ALLOWED: HashMap<[u8; STORE_HASH_LEN], u8> = HashMap::with_max_entries(65536, 0);

/// [`Action`] per [`Classification`], indexed by discriminant, set by userspace.
#[map]
static POLICY: Array<u8> = Array::with_max_entries(CLASSIFICATIONS as u32, 0);

const EPERM: i32 = 1;

const STORE_PREFIX: &[u8; 11] = b"/nix/store/";
const WRAPPER_PREFIX: &[u8; 14] = b"/run/wrappers/";

/// From `include/uapi/linux/magic.h`.
const TMPFS_MAGIC: u64 = 0x0102_1994;

#[inline(always)]
fn inode_flags(file: *mut file) -> Result<u8, i64> {
    let inode = unsafe { bpf_probe_read_kernel(&raw const (*file).f_inode)? };
    let nlink = unsafe { bpf_probe_read_kernel(&raw const (*inode).__bindgen_anon_1.i_nlink)? };
    let sb = unsafe { bpf_probe_read_kernel(&raw const (*inode).i_sb)? };
    let magic = unsafe { bpf_probe_read_kernel(&raw const (*sb).s_magic)? };

    let mut flags = 0u8;
    if nlink == 0 {
        flags |= FLAG_UNLINKED;
    }
    if magic == TMPFS_MAGIC {
        flags |= FLAG_TMPFS;
    }
    Ok(flags)
}

#[inline(always)]
fn classify(path: &[u8; 256], flags: u8) -> Classification {
    if flags & FLAG_UNLINKED != 0 {
        return if flags & FLAG_TMPFS != 0 {
            Classification::Memory
        } else {
            Classification::Deleted
        };
    }
    if path.starts_with(STORE_PREFIX) {
        if let Ok(hash) = <&[u8; STORE_HASH_LEN]>::try_from(
            &path[STORE_PREFIX.len()..STORE_PREFIX.len() + STORE_HASH_LEN],
        ) && unsafe { ALLOWED.get(hash) }.is_some()
        {
            return Classification::Closure;
        }
        return Classification::Store;
    }
    if path.starts_with(WRAPPER_PREFIX) {
        return Classification::Wrapper;
    }
    Classification::Outside
}

/// Falls back to [`Action::Audit`] so a missing or corrupt policy reports
/// rather than silently permitting.
#[inline(always)]
fn policy_for(classification: Classification) -> Action {
    POLICY
        .get(classification as u32)
        .copied()
        .and_then(Action::from_u8)
        .unwrap_or(Action::Audit)
}

/// Anything that goes wrong before a verdict is reached permits the exec.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    try_bprm_check_security(&ctx).unwrap_or(0)
}

fn try_bprm_check_security(ctx: &LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);
    let file = unsafe { (*bprm).file };

    let mut ev = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        comm: bpf_get_current_comm().unwrap_or_default(),
        path: [0u8; 256],
        classification: Classification::Outside as u8,
        action: Action::Allow as u8,
    };

    let f_path = unsafe { &raw mut (*file).__bindgen_anon_1.f_path };
    let ret =
        unsafe { bpf_path_d_path(f_path, ev.path.as_mut_ptr().cast::<c_char>(), ev.path.len()) };
    if ret < 0 {
        return Err(ret);
    }

    let classification = classify(&ev.path, inode_flags(file).unwrap_or(0));
    ev.classification = classification as u8;

    let action = policy_for(classification);
    ev.action = action as u8;
    if action == Action::Allow {
        return Ok(0);
    }

    info!(&ctx, "lsm hook bprm_check_security called");
    // a full ring buffer must not turn a deny into an allow
    let _ = EVENTS.output::<ExecEvent>(&ev, 0);

    if action == Action::Deny { Ok(-EPERM) } else { Ok(0) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
