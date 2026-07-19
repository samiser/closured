use aya::{Btf, maps::RingBuf, programs::Lsm};
#[rustfmt::skip]
use log::{debug, warn};
use closured_common::ExecEvent;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn handle_event(ev: &ExecEvent) {
    let path = cstr(&ev.path);
    let verdict = if path.starts_with("/nix/store/") {
        "store  "
    } else {
        "OUTSIDE"
    };
    println!(
        "[{verdict}] pid={} uid={} comm={} path={path}",
        ev.pid,
        ev.uid,
        cstr(&ev.comm)
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/closured"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf
        .program_mut("bprm_check_security")
        .unwrap()
        .try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)?;

    println!("closured: auditing execs, Ctrl-C to exit");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= core::mem::size_of::<ExecEvent>() {
                        let ev: ExecEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const ExecEvent)
                        };
                        handle_event(&ev);
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
