use std::{
    collections::HashSet,
    io::Write as _,
    path::{Path, PathBuf},
    process,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use aya::{
    Btf,
    maps::{Array, HashMap, RingBuf},
    programs::Lsm,
};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand, ValueEnum};
#[rustfmt::skip]
use log::{debug, warn};
use closured_common::{Action, CLASSIFICATIONS, Classification, ExecEvent, STORE_HASH_LEN};
use serde::Serialize;
use tokio::{
    io::{
        AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader, Interest,
        unix::AsyncFd,
    },
    net::{UnixListener, UnixStream},
    signal,
    sync::{mpsc, oneshot},
};

const ECS_VERSION: &str = "8.17";

#[derive(Parser)]
#[command(version, about = "eBPF LSM exec auditor for NixOS closures")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    args: Args,
}

#[derive(Subcommand)]
enum Command {
    /// Allowlist a system closure before activating it. Returns once the
    /// allowlist is updated, so the switch is safe immediately afterwards.
    Preload {
        /// System to activate, e.g. the `result` symlink from `nixos-rebuild build`
        path: PathBuf,
    },
}

#[derive(clap::Args)]
struct Args {
    /// Output format for events on stdout
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,

    /// Report every exec, not just those outside the allowed closure
    #[arg(long)]
    all: bool,

    /// Block execs outside the allowed closure rather than only reporting them
    #[arg(long)]
    enforce: bool,

    /// Per-classification overrides, e.g. --policy store=deny,wrapper=allow
    #[arg(long, value_delimiter = ',', value_parser = parse_policy)]
    policy: Vec<(Classification, Action)>,

    /// Closure roots whose requisites are allowed (defaults to
    /// /run/current-system and /run/booted-system when present)
    #[arg(long = "root")]
    roots: Vec<PathBuf>,

    /// Socket the daemon serves `preload` on, and the client connects to
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET, global = true)]
    control_socket: PathBuf,

    /// Seconds a preloaded closure stays allowed if it is never activated
    #[arg(long, default_value_t = 900)]
    preload_ttl: u64,
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
    outcome: &'static str,
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
    action: &'static str,
}

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

fn parse_policy(spec: &str) -> Result<(Classification, Action), String> {
    let (class, action) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected <classification>=<action>, got `{spec}`"))?;
    let class = Classification::ALL
        .into_iter()
        .find(|c| c.as_str() == class)
        .ok_or_else(|| {
            let known = Classification::ALL.map(Classification::as_str).join(", ");
            format!("unknown classification `{class}`, expected one of: {known}")
        })?;
    let action = Action::ALL
        .into_iter()
        .find(|a| a.as_str() == action)
        .ok_or_else(|| {
            let known = Action::ALL.map(Action::as_str).join(", ");
            format!("unknown action `{action}`, expected one of: {known}")
        })?;
    Ok((class, action))
}

fn policy_table(args: &Args) -> [Action; CLASSIFICATIONS] {
    let mut table = [Action::Audit; CLASSIFICATIONS];
    table[Classification::Closure as usize] = Action::Allow;

    if args.enforce {
        for class in [
            Classification::Store,
            Classification::Memory,
            Classification::Deleted,
            Classification::Outside,
        ] {
            table[class as usize] = Action::Deny;
        }
    }
    if args.all {
        table[Classification::Closure as usize] = Action::Audit;
    }
    for (class, action) in &args.policy {
        table[*class as usize] = *action;
    }
    table
}

type StoreHash = [u8; STORE_HASH_LEN];

const DEFAULT_CONTROL_SOCKET: &str = "/run/closured/control";

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
        let out = process::Command::new("nix-store")
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

struct Preload {
    path: PathBuf,
    hashes: HashSet<StoreHash>,
    expires: Instant,
}

struct Allowlist {
    map: HashMap<aya::maps::MapData, StoreHash, u8>,
    closure: HashSet<StoreHash>,
    preloads: Vec<Preload>,
    installed: HashSet<StoreHash>,
}

impl Allowlist {
    fn sync(&mut self) -> (usize, usize) {
        let mut desired = self.closure.clone();
        for preload in &self.preloads {
            desired.extend(&preload.hashes);
        }

        let mut added = 0;
        let mut still_absent = Vec::new();
        for hash in desired.difference(&self.installed) {
            match self.map.insert(hash, 1, 0) {
                Ok(()) => added += 1,
                Err(e) => {
                    warn!("failed to insert closure path into allowlist (map full?): {e}");
                    still_absent.push(*hash);
                }
            }
        }

        let mut removed = 0;
        let mut still_present = Vec::new();
        for hash in self.installed.difference(&desired) {
            match self.map.remove(hash) {
                Ok(()) => removed += 1,
                Err(e) => {
                    warn!("failed to remove stale path from allowlist: {e}");
                    still_present.push(*hash);
                }
            }
        }

        for hash in still_absent {
            desired.remove(&hash);
        }
        desired.extend(still_present);
        self.installed = desired;
        (added, removed)
    }

    fn drop_covered_and_expired(&mut self, now: Instant) -> usize {
        let before = self.preloads.len();
        let closure = &self.closure;
        self.preloads.retain(|preload| {
            let reason = if preload.hashes.is_subset(closure) {
                "activated"
            } else if preload.expires <= now {
                "expired without being activated"
            } else {
                return true;
            };
            eprintln!("closured: preload {} {reason}", preload.path.display());
            false
        });
        before - self.preloads.len()
    }
}

type PreloadRequest = (PathBuf, oneshot::Sender<Result<usize, String>>);

const MAX_REQUEST: u64 = 4096;

async fn add_preload(
    allowlist: &mut Allowlist,
    path: PathBuf,
    ttl: Duration,
) -> Result<usize, String> {
    if !path.starts_with("/nix/store") {
        return Err(format!("{} is not a store path", path.display()));
    }
    let gathered = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || gather_closure(&[path])).await
    };
    let hashes = match gathered.unwrap_or_else(|e| Err(e.into())) {
        Ok(hashes) => hashes,
        Err(e) => return Err(format!("{e:#}")),
    };

    let total = hashes.len();
    allowlist.preloads.retain(|preload| preload.path != path);
    allowlist.preloads.push(Preload {
        path: path.clone(),
        hashes,
        expires: Instant::now() + ttl,
    });
    let (added, _) = allowlist.sync();
    eprintln!(
        "closured: preloaded {} ({total} paths, {added} newly allowed)",
        path.display()
    );
    Ok(added)
}

async fn serve_control_conn(
    mut stream: UnixStream,
    tx: mpsc::Sender<PreloadRequest>,
) -> anyhow::Result<()> {
    let peer = stream.peer_cred().context("reading peer credentials")?;
    let (readable, mut writable) = stream.split();

    let mut line = String::new();
    BufReader::new(readable.take(MAX_REQUEST))
        .read_line(&mut line)
        .await?;

    let reply = if peer.uid() != 0 {
        warn!("rejected control connection from uid {}", peer.uid());
        Err("permission denied".to_string())
    } else {
        match line.trim().split_once(' ') {
            Some(("preload", path)) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                if tx.send((PathBuf::from(path), reply_tx)).await.is_err() {
                    Err("closured is shutting down".to_string())
                } else {
                    reply_rx
                        .await
                        .unwrap_or_else(|_| Err("request dropped".to_string()))
                }
            }
            _ => Err(format!("unknown command `{}`", line.trim())),
        }
    };

    let line = match reply {
        Ok(added) => format!("ok {added}\n"),
        Err(msg) => format!("err {msg}\n"),
    };
    writable.write_all(line.as_bytes()).await?;
    writable.shutdown().await?;
    Ok(())
}

fn bind_control_socket(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(anyhow::Error::new(e).context(format!("removing stale {}", path.display())));
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .with_context(|| format!("restricting {} to its owner", path.display()))?;
    Ok(listener)
}

async fn next_root_change(watcher: Option<&AsyncFd<std::os::fd::OwnedFd>>) {
    use std::os::fd::AsRawFd as _;

    let Some(watcher) = watcher else {
        return std::future::pending().await;
    };
    loop {
        let Ok(mut guard) = watcher.readable().await else {
            continue;
        };
        let mut buf = [0u8; 4096];
        let fd = watcher.get_ref().as_raw_fd();
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        guard.clear_ready();
        return;
    }
}

async fn next_expiry(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

async fn run_preload(socket: &Path, path: &Path) -> anyhow::Result<()> {
    let canonical =
        std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;

    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {} (is closured running?)", socket.display()))?;
    stream
        .write_all(format!("preload {}\n", canonical.display()).as_bytes())
        .await?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).await?;
    match reply.trim().split_once(' ') {
        Some(("ok", added)) => {
            eprintln!(
                "closured: preloaded {} ({added} newly allowed)",
                canonical.display()
            );
            Ok(())
        }
        Some(("err", msg)) => anyhow::bail!("closured refused the preload: {msg}"),
        _ => anyhow::bail!("unexpected reply from closured: {:?}", reply.trim()),
    }
}

fn handle_event(ev: &ExecEvent, path: &[u8], format: Format) -> anyhow::Result<()> {
    let path = cstr(path);
    let comm = cstr(&ev.comm);
    let (Some(classification), Some(action)) = (
        Classification::from_u8(ev.classification),
        Action::from_u8(ev.action),
    ) else {
        warn!(
            "dropping malformed event (classification {}, action {}): pid={} path={path}",
            ev.classification, ev.action, ev.pid
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
            let denied = if action == Action::Deny {
                " DENIED"
            } else {
                ""
            };
            println!(
                "[{label}]{denied} pid={} uid={} comm={comm} path={path}",
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
                    outcome: if action == Action::Deny {
                        "failure"
                    } else {
                        "success"
                    },
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
                    action: action.as_str(),
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
    let cli = Cli::parse();
    let args = cli.args;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Some(Command::Preload { path }) = &cli.command {
        return run_preload(&args.control_socket, path).await;
    }

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

    let policy = policy_table(&args);
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
    let mut ebpf = with_privilege_hint(aya::EbpfLoader::new().load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/closured")
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
    // Fill the allowlist and policy before the hook attaches, so no exec sees a
    // partial closure or an unset policy
    let mut allowlist = Allowlist {
        map: HashMap::try_from(ebpf.take_map("ALLOWED").unwrap())?,
        closure,
        preloads: Vec::new(),
        installed: HashSet::new(),
    };
    allowlist.sync();

    let mut policy_map: Array<_, u8> = Array::try_from(ebpf.take_map("POLICY").unwrap())?;
    for (class, action) in policy.into_iter().enumerate() {
        policy_map.set(class as u32, action as u8, 0)?;
    }

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
    let mode = if policy.contains(&Action::Deny) {
        "enforcing"
    } else {
        "auditing"
    };
    eprintln!(
        "closured: {mode} execs against {} closure paths from {} root(s), Ctrl-C to exit",
        allowlist.closure.len(),
        roots.len()
    );

    let (control_tx, mut control_rx) = mpsc::channel::<PreloadRequest>(8);
    match bind_control_socket(&args.control_socket) {
        Ok(listener) => {
            eprintln!(
                "closured: accepting preloads on {}",
                args.control_socket.display()
            );
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let tx = control_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_control_conn(stream, tx).await {
                                    warn!("control connection failed: {e:#}");
                                }
                            });
                        }
                        Err(e) => warn!("control socket accept failed: {e}"),
                    }
                }
            });
        }
        Err(e) => warn!("preload unavailable: {e:#}"),
    }

    // refresh the allowlist when a root repoints; the tick catches missed events
    let watcher = match watch_root_dirs(&roots) {
        Ok(fd) => Some(AsyncFd::with_interest(fd, Interest::READABLE)?),
        Err(e) => {
            warn!("inotify unavailable, falling back to polling: {e:#}");
            None
        }
    };
    let preload_ttl = Duration::from_secs(args.preload_ttl);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            let soonest_expiry = allowlist.preloads.iter().map(|p| p.expires).min();
            let request = tokio::select! {
                _ = tick.tick() => None,
                Some(request) = control_rx.recv() => Some(request),
                () = next_root_change(watcher.as_ref()) => None,
                () = next_expiry(soonest_expiry) => None,
            };

            if let Some((path, reply)) = request {
                let _ = reply.send(add_preload(&mut allowlist, path, preload_ttl).await);
                continue;
            }

            let new_targets = root_targets(&roots);
            let closure_changed = new_targets != targets;
            if closure_changed {
                let gather_roots = roots.clone();
                let gathered =
                    tokio::task::spawn_blocking(move || gather_closure(&gather_roots)).await;
                match gathered.unwrap_or_else(|e| Err(e.into())) {
                    Ok(new_closure) => {
                        allowlist.closure = new_closure;
                        targets = new_targets;
                    }
                    Err(e) => {
                        warn!("closure refresh failed, will retry: {e:#}");
                        continue;
                    }
                }
            }

            let dropped = allowlist.drop_covered_and_expired(Instant::now());
            if closure_changed || dropped > 0 {
                let (added, removed) = allowlist.sync();
                eprintln!(
                    "closured: allowlist refreshed (+{added} -{removed}, {} total)",
                    allowlist.installed.len()
                );
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
                    let header = core::mem::size_of::<ExecEvent>();
                    if item.len() >= header {
                        let ev: ExecEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const ExecEvent)
                        };
                        handle_event(&ev, &item[header..], args.format)?;
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
