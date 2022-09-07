use crate::shm_conds::ShmConds;

#[cfg(all(feature = "autoinit", not(test)))]
use {
    crate::shm_branches,
    angora_common::{defs, fork_client},
    ctor::ctor,
    std::env,
    std::process,
};

#[cfg(all(feature = "autoinit", not(test)))]
#[ctor]
fn runtime_fast_ctor() {
    env_logger::init();

    if let Ok(branches_shm_id) = env::var(defs::BRANCHES_SHM_ENV_VAR) {
        let branches_shm_id = branches_shm_id
            .parse::<i32>()
            .expect("Could not parse shared memory ID.");
        shm_branches::map_branch_counting_shm(branches_shm_id);
    }

    if let Ok(cond_stmt_shm_id) = env::var(defs::COND_STMT_ENV_VAR) {
        let cond_stmt_shm_id = cond_stmt_shm_id
            .parse::<i32>()
            .expect("Could not parse shared memory ID.");
        ShmConds::global_init(cond_stmt_shm_id);
    };

    if let Ok(socket_path) = env::var(defs::FORKSRV_SOCKET_PATH_VAR) {
        fork_client::start(socket_path, true, true).unwrap_or_else(|error| match error {
            fork_client::Error::ShouldExit => process::exit(0),
            _ => {
                log::error!("Error in fork server: {}", error);
                process::exit(1);
            },
        });

        // Run by spawned children
        ShmConds::global().unwrap().reset();
    }
}

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
            conds.update_cmp(condition, arg1, arg2);
        }
    }

    condition
}

#[no_mangle]
pub extern "C" fn __angora_trace_switch(cmpid: u32, context: u32, condition: u64) -> u64 {
    if let Some(mut conds) = ShmConds::global() {
        if conds.check_match(cmpid, context) {
            return conds.update_switch(condition);
        }
    }

    condition
}
