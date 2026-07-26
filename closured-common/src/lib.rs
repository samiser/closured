#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub path: [u8; 256],
    pub classification: u8,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Classification {
    Closure = 0,
    Store = 1,
    Wrapper = 2,
    Memory = 3,
    Deleted = 4,
    Outside = 5,
}

impl Classification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closure => "closure",
            Self::Store => "store",
            Self::Wrapper => "wrapper",
            Self::Memory => "memory",
            Self::Deleted => "deleted",
            Self::Outside => "outside",
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Closure),
            1 => Some(Self::Store),
            2 => Some(Self::Wrapper),
            3 => Some(Self::Memory),
            4 => Some(Self::Deleted),
            5 => Some(Self::Outside),
            _ => None,
        }
    }
}

/// The executable's inode has no links (unlinked/anonymous): a memfd,
/// an `O_TMPFILE`, or a file deleted while held open.
pub const FLAG_UNLINKED: u8 = 1 << 0;

/// The executable is backed by tmpfs (superblock magic), i.e. RAM/swap
/// rather than a persistent filesystem.
pub const FLAG_TMPFS: u8 = 1 << 1;

/// Length of the base32 hash in `/nix/store/<hash>-<name>`.
pub const STORE_HASH_LEN: usize = 32;
