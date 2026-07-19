use std::io::Write as _;

use aya::{Btf, maps::RingBuf, programs::Lsm};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, ValueEnum};
#[rustfmt::skip]
use log::{debug, warn};
use closured_common::ExecEvent;
use serde::Serialize;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

const ECS_VERSION: &str = "8.17";

#[derive(Parser)]
#[command(version, about = "eBPF LSM exec auditor for NixOS closures")]
struct Args {
    /// Output format for events on stdout
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,

    /// Report every exec, not just those outside /nix/store
    #[arg(long)]
    all: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// ECS-shaped NDJSON
    Json,
    /// Human-readable text lines
    Text,
}

#[derive(Serialize)]
struct JsonEvent {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    ecs: EcsMeta,
    event: EventMeta,
    process: ProcessFields,
    user: UserFields,
    closured: ClosuredFields,
}

#[derive(Serialize)]
struct EcsMeta {
    version: &'static str,
}

#[derive(Serialize)]
struct EventMeta {
    kind: &'static str,
    category: [&'static str; 1],
    #[serde(rename = "type")]
    r#type: [&'static str; 1],
    action: &'static str,
    provider: &'static str,
}

#[derive(Serialize)]
struct ProcessFields {
    pid: u32,
    name: String,
    executable: String,
}

#[derive(Serialize)]
struct UserFields {
    id: String,
}

#[derive(Serialize)]
struct ClosuredFields {
    classification: &'static str,
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// What kind of thing ran. Policy outcomes (audited/denied) are expressed
/// via the ECS `event` fields instead so this can stay purely descriptive.
fn classify(path: &str) -> &'static str {
    if path.starts_with("/memfd:") {
        // memfd_create + execveat: d_path renders these as "/memfd:name (deleted)"
        "memory"
    } else if path.ends_with(" (deleted)") {
        // Unlinked file (O_TMPFILE, deleted binary) exec'd via a held fd,
        // e.g. through /proc/self/fd/N. Checked before the store prefix:
        // a deleted store path is not the closure's file anymore.
        //
        // TODO: move this detection into the eBPF program by checking the
        // inode link count (file->f_inode->i_nlink == 0) and carrying the
        // classification in ExecEvent, instead of relying on d_path's
        // " (deleted)" rendering convention, which a crafted path name
        // can spoof.
        "deleted"
    } else if path.starts_with("/nix/store/") {
        "store"
    } else {
        "outside"
    }
}

fn handle_event(ev: &ExecEvent, format: Format) -> anyhow::Result<()> {
    let path = cstr(&ev.path);
    let comm = cstr(&ev.comm);
    let classification = classify(&path);

    match format {
        Format::Text => {
            let label = match classification {
                "store" => "store  ",
                "memory" => "MEMORY ",
                "deleted" => "DELETED",
                _ => "OUTSIDE",
            };
            println!(
                "[{label}] pid={} uid={} comm={comm} path={path}",
                ev.pid, ev.uid
            );
        }
        Format::Json => {
            let event = JsonEvent {
                timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                ecs: EcsMeta {
                    version: ECS_VERSION,
                },
                event: EventMeta {
                    kind: "event",
                    category: ["process"],
                    r#type: ["start"],
                    action: "exec",
                    provider: "closured",
                },
                process: ProcessFields {
                    pid: ev.pid,
                    name: comm,
                    executable: path,
                },
                user: UserFields {
                    id: ev.uid.to_string(),
                },
                closured: ClosuredFields { classification },
            };
            let mut out = std::io::stdout().lock();
            serde_json::to_writer(&mut out, &event)?;
            out.write_all(b"\n")?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
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
    let mut ebpf = aya::EbpfLoader::new()
        .override_global("AUDIT_ALL", &u8::from(args.all), true)
        .load(aya::include_bytes_aligned!(concat!(
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

    // stderr, so stdout stays pure event output in json mode
    eprintln!("closured: auditing execs, Ctrl-C to exit");

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
                        handle_event(&ev, args.format)?;
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
