#![feature(c_variadic)]

pub mod callbacks;
pub mod context;
pub mod shm_branches;
pub mod shm_conds;

#[cfg(all(feature = "autoinit"))]
mod init;
#[cfg(all(feature = "autoinit"))]
mod libc_wrappers;
#[cfg(all(feature = "autoinit"))]
mod tainter;
