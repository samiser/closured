# closured

> [!WARNING]
> **Work in Progress:** This repository is actively under development and things
> may change or break without warning

closured uses eBPF LSM hooks to ensure your NixOS system only executes what its
closure declares, either auditing or blocking other attempted executions

On startup closured builds an allowlist from the requisites of its closure roots
(`/run/current-system`, `/run/booted-system` and `/nix/var/nix/profiles/system`
by default) and reports any exec that falls outside it. Events are classified
as:

- `closure`: a store path in the allowed closure (only reported with `--all`)
- `store`: a store path not in the allowed closure
- `wrapper`: a setuid wrapper under `/run/wrappers`
- `memory` / `deleted`: an unlinked executable (memfd or deleted file)
- `outside`: anything else

The allowlist refreshes automatically when a closure root changes, so a deploy
is picked up without a restart.

## Prerequisites

1. kernel >= 6.12 with BTF (`/sys/kernel/btf/vmlinux`)
2. the BPF LSM enabled (`bpf` present in the active LSM list:
   `cat /sys/kernel/security/lsm`)

## Build & Run

```shell
nix build
sudo ./result/bin/closured   # loading the eBPF program needs root
```

or just

```shell
sudo nix run
```

## NixOS module

The flake exports a NixOS module that runs closured as a hardened systemd
service:

```nix
{
  inputs.closured.url = "github:samiser/closured";

  imports = [inputs.closured.nixosModules.default];
  services.closured.enable = true;
```

Events are logged as NDJSON: `journalctl -u closured -o cat | grep '^{' | jq`

## Deploying under `--enforce`

Refreshing the allowlist means shelling out to `nix-store --query --requisites`,
which takes long enough that `switch-to-configuration` (a binary from the new
generation) can run before the refresh happens and be denied. `closured preload`
fixes this by allowlisting a closure before you activate it:

```shell
nixos-rebuild build
sudo closured preload ./result
nixos-rebuild switch
```

`preload` returns only once the hashes are in the BPF map, so the switch is safe
the moment it exits.

`nixos-rebuild boot` followed by a reboot needs no preload at all because at
boot `/run/current-system` already points at the new generation.

Preloads are held until the closure catches up with them, and are removed after
`--preload-ttl` seconds (default 900) if the system is never activated, so
abandoning a build does not leave it executable indefinitely.

## Development

`nix develop` gives you a shell where you can build with cargo

`nix flake check` runs two NixOS VM tests:

- `checks.<system>.vm` covers enforcement, the control socket and preload
  expiry.
- `checks.<system>.switch` builds a second system generation, preloads it and
  activates it under `--enforce`, then checks the preload is consumed once the
  closure catches up.

## License

With the exception of eBPF code, closured is distributed under the terms of
either the [MIT license] or the [Apache License] (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
