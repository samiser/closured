# closured

> [!WARNING]
> **Work in Progress:** This repository is actively under development and things may change or break without warning

closured uses eBPF LSM hooks to ensure your NixOS system only executes what its closure declares, either auditing or blocking other attempted executions

## Prerequisites

`nix develop` gives you a build environment

Runtime requirements on the target machine:

1. kernel >= 6.12 with BTF (`/sys/kernel/btf/vmlinux`)
2. the BPF LSM enabled (`bpf` present in the active LSM list: `cat /sys/kernel/security/lsm`)

## Build & Run

Within the devshell use `cargo build`, `cargo check`, etc. as normal. Run with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the program.

## License

With the exception of eBPF code, closured is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
