use bitflags::bitflags;
use std::io;

mod internal {
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/afl_snapshot_bindings.rs"));
}

/// Initializes the snapshotting system.
///
/// # Errors
///
/// This function will return an error if the `ioctl` device created by the
/// kernel module cannot be opened.
pub fn init() -> Result<(), io::Error> {
    let res = unsafe { internal::afl_snapshot_init() };
    if res >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

bitflags! {
    pub struct ConfigFlags: i32 {
        /// Trace new mmap-ed areas and unmap them on restore.
        const MMAP = 1;
        /// Do not snapshot any page (by default all writable not-shared pages are snapshotted).
        const BLOCK = 2;
        /// Snapshot file descriptor state, close newly opened descriptors.
        const FDS = 4;
        /// Snapshot registers state.
        const REGS = 8;
        /// Perform a restore when `exit_group` is invoked.
        const EXIT = 16;
        /// Disable `COW`, restore all the snapshotted pages.
        const NOCOW = 32;
        /// Do not snapshot stack pages.
        const NOSTACK = 64;
    }
}

/// Takes a snapshot of the current program.
///
/// This function returns `true` if a snapshot was taken, it returns `false`
/// when resuming from a snapshot that was already taken.
pub fn take(config: ConfigFlags) -> bool {
    let res = unsafe { internal::afl_snapshot_take(config.bits()) };
    match res {
        0 => false,
        1 => true,
        _ => panic!("Unexpected return value from afl_snapshot_take: {}", res),
    }
}

/// Removes the snapshot for the current process.
///
/// Even after calling this function, [`take`] cannot be used again.
#[allow(dead_code)]
pub fn clean() {
    unsafe { internal::afl_snapshot_clean() };
}
