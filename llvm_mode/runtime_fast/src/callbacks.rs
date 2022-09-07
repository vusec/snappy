use crate::shm_conds::ShmConds;
use backtrace::Backtrace;

#[no_mangle]
pub extern "C" fn __angora_trace_cmp(
    condition: u32,
    cmpid: u32,
    context: u32,
    arg1: u64,
    arg2: u64,
) -> u32 {
    if let Some(mut conds) = ShmConds::global() {
        if conds.check_match(cmpid, context) {
            log::trace!(
                "Match: [CMP] id: {}, ctx: {}, arg1: {}, arg2: {}, cond: {}",
                cmpid,
                context,
                arg1,
                arg2,
                condition,
            );
            log::trace!("Backtrace:\n{:?}", Backtrace::new());

            conds.update_cmp(condition, arg1, arg2);
        }
    }

    condition
}

#[no_mangle]
pub extern "C" fn __angora_trace_switch(cmpid: u32, context: u32, condition: u64) -> u64 {
    if let Some(mut conds) = ShmConds::global() {
        if conds.check_match(cmpid, context) {
            log::trace!(
                "Match: [SWITCH] id: {}, ctx: {}, val: {}",
                cmpid,
                context,
                condition,
            );
            log::trace!("Backtrace:\n{:?}", Backtrace::new());

            conds.update_switch(condition);
        }
    }

    condition
}
