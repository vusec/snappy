// map branch counting shared memory.

use angora_common::{config::BRANCHES_SIZE, shm};
use std::process;

type BranchBuf = [u8; BRANCHES_SIZE];

/// Dummy area used for instrumentation output for standalone runs.
static mut __ANGORA_AREA_INITIAL: BranchBuf = [255; BRANCHES_SIZE];

#[no_mangle]
pub static mut __angora_area_ptr: *const u8 = unsafe { __ANGORA_AREA_INITIAL.as_ptr() };

pub fn map_branch_counting_shm(branches_shm_id: i32) {
    let mem = shm::SHM::<BranchBuf>::from_id(branches_shm_id);
    if mem.is_fail() {
        eprintln!("fail to load shm");
        process::exit(1);
    }

    // This function is called only from within a constructor and
    // `angora_area_ptr` is written only here.
    unsafe {
        __angora_area_ptr = mem.get_ptr().cast::<u8>();
    }
}
