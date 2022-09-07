// corresponding to fuzzer/src/cond_stmt/shm_conds.rs

use super::context;
use angora_common::{cond_stmt_base::CondStmtBase, shm};
use once_cell::sync::OnceCell;
use std::{
    process,
    sync::{Mutex, MutexGuard},
};

// TODO: Make it an AtomicU32 or a thread-local variable. This is fine only for
// single-threaded programs.
#[no_mangle]
static mut __angora_cond_cmpid: u32 = 0;

#[inline(always)]
fn set_cmpid(cid: u32) {
    unsafe {
        __angora_cond_cmpid = cid;
    }
}

#[derive(Debug)]
pub struct ShmConds {
    cond: shm::SHM<CondStmtBase>,
    rt_order: u32,
}

// shm contains pointer..
unsafe impl Send for ShmConds {}

// Drop in common/shm.rs:
// Though SHM<T> implement "drop" function, but it won't call (as we want) since ShmConds is in lazy_static!
impl ShmConds {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        let lock = SHM_CONDS.get()?;
        Some(lock.lock().expect("SHM_CONDS mutex poisoned"))
    }

    pub fn global_init(shm_id: i32) {
        let cond = shm::SHM::<CondStmtBase>::from_id(shm_id);
        if cond.is_fail() {
            process::exit(1);
        }

        SHM_CONDS
            .set(Mutex::new(Self { cond, rt_order: 0 }))
            .expect("ShmConds already initialized!");
    }

    #[inline(always)]
    fn mark_reachable(&mut self, condition: u32) {
        self.cond.lb1 = condition;
    }

    pub fn check_match(&mut self, cmpid: u32, context: u32) -> bool {
        if self.cond.cmpid == cmpid && self.cond.context == context {
            self.rt_order += 1;
            if self.cond.order & 0xFFFF == self.rt_order {
                return true;
            }
        }
        false
    }

    pub fn update_cmp(&mut self, condition: u32, arg1: u64, arg2: u64) -> u32 {
        self.cond.arg1 = arg1;
        self.cond.arg2 = arg2;
        self.rt_order = 0x8000;
        self.mark_reachable(condition);
        set_cmpid(0);
        condition
    }

    pub fn update_switch(&mut self, condition: u64) -> u64 {
        self.cond.arg1 = condition;
        self.rt_order = 0x8000;
        self.mark_reachable((condition == self.cond.arg2) as u32);
        set_cmpid(0);
        condition
    }

    pub fn reset(&mut self) {
        self.rt_order = 0;
        set_cmpid(self.cond.cmpid);
        context::reset_context();
    }
}

static SHM_CONDS: OnceCell<Mutex<ShmConds>> = OnceCell::new();
