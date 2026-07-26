use std::{collections::HashSet, io::Write as _, path::PathBuf, process::Command, time::Duration};

use anyhow::Context as _;
use aya::{
    Btf,
    maps::{HashMap, RingBuf},
    programs::Lsm,
};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, ValueEnum};
#[rustfmt::skip]
use log::{debug, warn};
use closured_common::{Classification, ExecEvent, STORE_HASH_LEN};
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

    /// Report every exec, not just those outside the allowed closure
    #[arg(long)]
    all: bool,

    /// Closure roots whose requisites are allowed (defaults to
    /// /run/current-system and /run/booted-system when present)
    #[arg(long = "root")]
    roots: Vec<PathBuf>,
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

/// Adds a privileges hint when an eBPF setup step failed on permissions for a friendlier error
fn with_privilege_hint<T>(res: Result<T, impl Into<anyhow::Error>>) -> anyhow::Result<T> {
    let err = match res {
        Ok(v) => return Ok(v),
        Err(e) => e.into(),
    };
    let permission = err
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| matches!(io.raw_os_error(), Some(libc::EPERM | libc::EACCES)));
    if permission {
        Err(err.context("insufficient privileges for loading the eBPF program (try sudo)"))
    } else {
        Err(err)
    }
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

type StoreHash = [u8; STORE_HASH_LEN];

// the system profile repoints before activation, so a deploy is allowed early
const DEFAULT_ROOTS: [&str; 3] = [
    "/run/current-system",
    "/run/booted-system",
    "/nix/var/nix/profiles/system",
];

fn store_hash(path: &str) -> Option<StoreHash> {
    let rest = path.strip_prefix("/nix/store/")?;
    rest.as_bytes().get(..STORE_HASH_LEN)?.try_into().ok()
}

fn closure_roots(args_roots: &[PathBuf]) -> Vec<PathBuf> {
    if !args_roots.is_empty() {
        return args_roots.to_vec();
    }
    DEFAULT_ROOTS
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

fn gather_closure(roots: &[PathBuf]) -> anyhow::Result<HashSet<StoreHash>> {
    let targets: HashSet<PathBuf> = roots
        .iter()
        .map(|root| std::fs::canonicalize(root).unwrap_or_else(|_| root.clone()))
        .collect();

    let mut hashes = HashSet::new();
    for root in targets {
        let out = Command::new("nix-store")
            .args(["--query", "--requisites"])
            .arg(&root)
            .output()
            .context("running nix-store (is it on PATH?)")?;
        if !out.status.success() {
            anyhow::bail!(
                "nix-store --query --requisites {} failed: {}",
                root.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(hash) = store_hash(line.trim()) {
                hashes.insert(hash);
            }
        }
    }
    Ok(hashes)
}

fn root_targets(roots: &[PathBuf]) -> Vec<Option<PathBuf>> {
    roots
        .iter()
        .map(|root| std::fs::canonicalize(root).ok())
        .collect()
}

/// inotify fd on the roots' parent dirs, so a repointed root is seen immediately
fn watch_root_dirs(roots: &[PathBuf]) -> anyhow::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()).context("inotify_init1"));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let dirs: HashSet<_> = roots.iter().filter_map(|root| root.parent()).collect();
    for dir in dirs {
        use std::os::unix::ffi::OsStrExt as _;
        let c_dir = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
        let mask = libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM | libc::IN_DELETE;
        let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c_dir.as_ptr(), mask) };
        if wd < 0 {
            warn!(
                "failed to watch {} for closure changes: {}",
                dir.display(),
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(fd)
}

fn populate_allowed(
    allowed: &mut HashMap<aya::maps::MapData, StoreHash, u8>,
    old: &HashSet<StoreHash>,
    new: &HashSet<StoreHash>,
) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    for hash in new.difference(old) {
        match allowed.insert(hash, 1, 0) {
            Ok(()) => added += 1,
            Err(e) => warn!("failed to insert closure path into allowlist (map full?): {e}"),
        }
    }
    for hash in old.difference(new) {
        match allowed.remove(hash) {
            Ok(()) => removed += 1,
            Err(e) => warn!("failed to remove stale path from allowlist: {e}"),
        }
    }
    (added, removed)
}

fn handle_event(ev: &ExecEvent, format: Format) -> anyhow::Result<()> {
    let path = cstr(&ev.path);
    let comm = cstr(&ev.comm);
    let Some(classification) = Classification::from_u8(ev.classification) else {
        warn!(
            "dropping event with unknown classification {}: pid={} path={path}",
            ev.classification, ev.pid
        );
        return Ok(());
    };

    match format {
        Format::Text => {
            let label = match classification {
                Classification::Closure => "closure",
                Classification::Store => "STORE  ",
                Classification::Wrapper => "wrapper",
                Classification::Memory => "MEMORY ",
                Classification::Deleted => "DELETED",
                Classification::Outside => "OUTSIDE",
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
                closured: ClosuredFields {
                    classification: classification.as_str(),
                },
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

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

    let roots = closure_roots(&args.roots);
    if roots.is_empty() {
        warn!("no closure roots found; every store exec will be reported");
    }
    let closure = gather_closure(&roots)?;
    let mut targets = root_targets(&roots);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = with_privilege_hint(
        aya::EbpfLoader::new()
            .override_global("AUDIT_ALL", &u8::from(args.all), true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/closured"
            ))),
    )?;
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
    // Fill the allowlist before the hook attaches so no exec sees a partial closure
    let mut allowed: HashMap<_, StoreHash, u8> = HashMap::try_from(ebpf.take_map("ALLOWED").unwrap())?;
    populate_allowed(&mut allowed, &HashSet::new(), &closure);

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf
        .program_mut("bprm_check_security")
        .unwrap()
        .try_into()?;
    with_privilege_hint(program.load("bprm_check_security", &btf))?;
    with_privilege_hint(program.attach())?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)?;

    // stderr, so stdout stays pure event output in json mode
    eprintln!(
        "closured: auditing execs against {} closure paths from {} root(s), Ctrl-C to exit",
        closure.len(),
        roots.len()
    );

    // refresh the allowlist when a root repoints; the tick catches missed events
    let watcher = match watch_root_dirs(&roots) {
        Ok(fd) => Some(AsyncFd::with_interest(fd, Interest::READABLE)?),
        Err(e) => {
            warn!("inotify unavailable, falling back to polling: {e:#}");
            None
        }
    };
    tokio::spawn(async move {
        use std::os::fd::AsRawFd as _;
        let mut closure = closure;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            match &watcher {
                Some(watcher) => {
                    tokio::select! {
                        _ = tick.tick() => {}
                        guard = watcher.readable() => {
                            let Ok(mut guard) = guard else { continue };
                            let mut buf = [0u8; 4096];
                            let fd = watcher.get_ref().as_raw_fd();
                            while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0
                            {}
                            guard.clear_ready();
                        }
                    }
                }
                None => {
                    tick.tick().await;
                }
            }
            let new_targets = root_targets(&roots);
            if new_targets == targets {
                continue;
            }
            let gather_roots = roots.clone();
            let gathered =
                tokio::task::spawn_blocking(move || gather_closure(&gather_roots)).await;
            match gathered.unwrap_or_else(|e| Err(e.into())) {
                Ok(new_closure) => {
                    let (added, removed) = populate_allowed(&mut allowed, &closure, &new_closure);
                    closure = new_closure;
                    targets = new_targets;
                    eprintln!(
                        "closured: closure changed, allowlist refreshed (+{added} -{removed}, {} total)",
                        closure.len()
                    );
                }
                Err(e) => warn!("closure refresh failed, will retry: {e:#}"),
            }
        }
    });

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
