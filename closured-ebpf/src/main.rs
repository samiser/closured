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
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use closured_common::ExecEvent;
use vmlinux::{linux_binprm, path};

#[allow(improper_ctypes)]
unsafe extern "C" {
    fn bpf_path_d_path(path: *mut path, buf: *mut c_char, buf__sz: usize) -> c_int;
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let _ = try_bprm_check_security(&ctx).unwrap_or(0);
    0
}

fn try_bprm_check_security(ctx: &LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);

    let mut ev = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        comm: bpf_get_current_comm().unwrap_or_default(),
        path: [0u8; 256],
    };

    let file = unsafe { (*bprm).file };
    let f_path = unsafe { &raw mut (*file).__bindgen_anon_1.f_path };
    let ret =
        unsafe { bpf_path_d_path(f_path, ev.path.as_mut_ptr().cast::<c_char>(), ev.path.len()) };
    if ret < 0 {
        return Err(ret);
    }

    info!(&ctx, "lsm hook bprm_check_security called");
    EVENTS.output::<ExecEvent>(&ev, 0)?;
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
