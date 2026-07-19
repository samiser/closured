use std::{fs, path::Path, process::Command};

use anyhow::{Context as _, anyhow, bail, ensure};
use aya_build::Toolchain;

/// kfuncs called from the eBPF crate. Each gets an extern FUNC entry in a
/// `.ksyms` BTF datasec, which aya's loader uses to resolve the call against
/// kernel BTF at load time.
const KFUNCS: &[&str] = &["bpf_path_d_path"];

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "closured-ebpf")
        .ok_or_else(|| anyhow!("closured-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    // rustc drops `#[link_section = ".ksyms"]` on foreign fns and bpf-linker
    // doesn't synthesize BTF for extern declarations (bpf-linker#317), so the
    // object comes out with the call relocation but without the `.ksyms` BTF
    // datasec that aya-obj's extern resolution requires. Splice it in here,
    // mirroring what clang emits for `__attribute__((section(".ksyms")))`.
    let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
    let obj = Path::new(&out_dir).join("closured");
    inject_kfunc_externs(&obj, KFUNCS)
        .with_context(|| format!("injecting kfunc BTF externs into {}", obj.display()))
}

fn inject_kfunc_externs(obj: &Path, kfuncs: &[&str]) -> anyhow::Result<()> {
    let elf = fs::read(obj)?;
    let btf = extract_section(&elf, ".BTF")?;

    let Some(patched) = patch_btf(&btf, kfuncs)? else {
        return Ok(()); // already injected
    };

    let btf_path = obj.with_extension("btf.patched");
    fs::write(&btf_path, &patched)?;
    let status = Command::new("llvm-objcopy")
        .arg(format!("--update-section=.BTF={}", btf_path.display()))
        .arg(obj)
        .status()
        .context("running llvm-objcopy (is it on PATH?)")?;
    ensure!(status.success(), "llvm-objcopy failed: {status}");
    Ok(())
}

/// Returns the contents of the named section of a 64-bit little-endian ELF.
fn extract_section(elf: &[u8], want: &str) -> anyhow::Result<Vec<u8>> {
    let u16at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap());
    let u32at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u64at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap());

    ensure!(
        elf.len() > 0x40 && &elf[..4] == b"\x7fELF" && elf[4] == 2 && elf[5] == 1,
        "not a 64-bit little-endian ELF"
    );
    let shoff = u64at(0x28) as usize;
    let shentsize = u16at(0x3a) as usize;
    let shnum = u16at(0x3c) as usize;
    let shstrndx = u16at(0x3e) as usize;

    let sh = |i: usize| shoff + i * shentsize;
    let strtab_off = u64at(sh(shstrndx) + 0x18) as usize;

    for i in 0..shnum {
        let name_off = strtab_off + u32at(sh(i)) as usize;
        let name_end = elf[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off + p)
            .ok_or_else(|| anyhow!("unterminated section name"))?;
        if &elf[name_off..name_end] == want.as_bytes() {
            let off = u64at(sh(i) + 0x18) as usize;
            let size = u64at(sh(i) + 0x20) as usize;
            return Ok(elf[off..off + size].to_vec());
        }
    }
    bail!("section {want} not found")
}

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_FUNC_EXTERN: u32 = 2;
const BTF_INT_SIGNED: u32 = 1;

/// Appends, for each kfunc: FUNC_PROTO + extern FUNC entries, all referenced
/// from a new `.ksyms` DATASEC. Returns None if a `.ksyms` datasec already
/// exists (nothing to do). aya-obj's signature check against kernel BTF is
/// structural (kind-compatible, names ignored), so minimal param types
/// suffice; the kernel verifies the call site against its own BTF anyway.
fn patch_btf(btf: &[u8], kfuncs: &[&str]) -> anyhow::Result<Option<Vec<u8>>> {
    ensure!(btf.len() >= 24, "BTF too short");
    let u32at = |o: usize| u32::from_le_bytes(btf[o..o + 4].try_into().unwrap());
    ensure!(
        u16::from_le_bytes(btf[0..2].try_into().unwrap()) == 0xeb9f,
        "bad BTF magic"
    );
    let hdr_len = u32at(4) as usize;
    let (type_off, type_len) = (u32at(8) as usize, u32at(12) as usize);
    let (str_off, str_len) = (u32at(16) as usize, u32at(20) as usize);
    ensure!(
        type_off == 0 && str_off == type_len,
        "unexpected BTF section layout"
    );

    let types = &btf[hdr_len + type_off..][..type_len];
    let strings = &btf[hdr_len + str_off..][..str_len];

    // Walk existing types to find the next free type id, and bail out
    // early if a `.ksyms` datasec is already present (idempotency).
    let mut next_id = 1u32;
    let mut off = 0usize;
    while off < types.len() {
        ensure!(types.len() - off >= 12, "truncated BTF type record");
        let name_off = u32::from_le_bytes(types[off..off + 4].try_into().unwrap()) as usize;
        let info = u32::from_le_bytes(types[off + 4..off + 8].try_into().unwrap());
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        if kind == BTF_KIND_DATASEC
            && strings.get(name_off..name_off + 7) == Some(b".ksyms\0".as_ref())
        {
            return Ok(None);
        }
        let extra = match kind {
            1 => 4,                    // INT
            2 | 7..=12 | 16 | 18 => 0, // PTR FWD TYPEDEF cvr FUNC FLOAT TYPE_TAG
            3 => 12,                   // ARRAY
            4 | 5 => vlen * 12,        // STRUCT UNION
            6 => vlen * 8,             // ENUM
            13 => vlen * 8,            // FUNC_PROTO
            14 | 17 => 4,              // VAR DECL_TAG
            15 | 19 => vlen * 12,      // DATASEC ENUM64
            k => bail!("unknown BTF kind {k}"),
        };
        off += 12 + extra;
        next_id += 1;
    }

    let mut new_types: Vec<u8> = Vec::new();
    let mut new_strs: Vec<u8> = Vec::new();
    let mut add_str = |s: &str| -> u32 {
        let off = str_len + new_strs.len();
        new_strs.extend_from_slice(s.as_bytes());
        new_strs.push(0);
        off as u32
    };
    let mut add_type = |name_off: u32, info: u32, size_or_type: u32, extra: &[u32]| -> u32 {
        for w in [name_off, info, size_or_type].iter().chain(extra) {
            new_types.extend_from_slice(&w.to_le_bytes());
        }
        let id = next_id;
        next_id += 1;
        id
    };
    let info = |kind: u32, vlen: u32| (kind << 24) | vlen;

    let int_id = add_type(
        add_str("int"),
        info(BTF_KIND_INT, 0),
        4,
        &[(BTF_INT_SIGNED << 24) | 32],
    );
    let char_id = add_type(
        add_str("char"),
        info(BTF_KIND_INT, 0),
        1,
        &[(BTF_INT_SIGNED << 24) | 8],
    );
    let ulong_id = add_type(add_str("unsigned long"), info(BTF_KIND_INT, 0), 8, &[64]);
    let path_id = add_type(add_str("path"), info(BTF_KIND_STRUCT, 0), 0, &[]);
    let ptr_path = add_type(0, info(BTF_KIND_PTR, 0), path_id, &[]);
    let ptr_char = add_type(0, info(BTF_KIND_PTR, 0), char_id, &[]);
    let (p_path, p_buf, p_sz) = (add_str("path"), add_str("buf"), add_str("buf__sz"));

    let mut func_ids = Vec::new();
    for name in kfuncs {
        let proto = add_type(
            0,
            info(BTF_KIND_FUNC_PROTO, 3),
            int_id,
            &[p_path, ptr_path, p_buf, ptr_char, p_sz, ulong_id],
        );
        func_ids.push(add_type(
            add_str(name),
            info(BTF_KIND_FUNC, BTF_FUNC_EXTERN),
            proto,
            &[],
        ));
    }

    let ksyms_str = add_str(".ksyms");
    let entries: Vec<u32> = func_ids.iter().flat_map(|&id| [id, 0, 0]).collect();
    add_type(
        ksyms_str,
        info(BTF_KIND_DATASEC, kfuncs.len() as u32),
        0,
        &entries,
    );

    let mut out = btf[..hdr_len].to_vec();
    out[12..16].copy_from_slice(&((type_len + new_types.len()) as u32).to_le_bytes());
    out[16..20].copy_from_slice(&((str_off + new_types.len()) as u32).to_le_bytes());
    out[20..24].copy_from_slice(&((str_len + new_strs.len()) as u32).to_le_bytes());
    out.extend_from_slice(types);
    out.extend_from_slice(&new_types);
    out.extend_from_slice(strings);
    out.extend_from_slice(&new_strs);
    Ok(Some(out))
}
