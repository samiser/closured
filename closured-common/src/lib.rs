#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub path: [u8; 256],
    pub flags: u8,
}

/// The executable's inode has no links (unlinked/anonymous): a memfd,
/// an `O_TMPFILE`, or a file deleted while held open.
pub const FLAG_UNLINKED: u8 = 1 << 0;

/// The executable is backed by tmpfs (superblock magic), i.e. RAM/swap
/// rather than a persistent filesystem.
pub const FLAG_TMPFS: u8 = 1 << 1;
