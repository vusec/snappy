use crate::{libc_wrappers, shm_branches, shm_conds::ShmConds, tainter::TainterBuilder};
use angora_common::defs;
use ctor::ctor;
use std::{env, process};

/// Exit code for when the instrumentation failed
pub const FAILURE_EXIT_CODE: i32 = 24;

fn log_mapped_memory() {
    let me = procfs::process::Process::myself().unwrap();

    log::trace!("process rss: {} pages", me.stat().unwrap().rss);

    let mut total_rss = 0;
    log::trace!("maps:");
    for (map, map_data) in me.smaps().unwrap() {
        if let Some(rss) = map_data.map.get("Rss") {
            total_rss += rss;
            log::trace!(
                "  rss: {} pages,\tperms: {}, addr: ({:#14x},{:#14x})\tpath: {:?}",
                rss / 4096,
                map.perms,
                map.address.0,
                map.address.1,
                map.pathname
            );
        }
    }
    log::trace!("total rss: {} pages", total_rss / 4096);
}

#[ctor]
fn runtime_fast_ctor() {
    libc_wrappers::with_instrumentation_disabled(|| {
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

        if log::log_enabled!(log::Level::Trace) {
            log_mapped_memory();
        }

        let mut tainter_builder = TainterBuilder::new();

        if let Some(input_file) = env::var_os(defs::INPUT_FILE_ENV_VAR) {
            tainter_builder.tainted_file_path(input_file.into());
        }

        if let Some(socket_path) = env::var_os(defs::FORKSRV_SOCKET_PATH_VAR) {
            tainter_builder.forkserver_socket_path(socket_path.into());
        }

        tainter_builder.build_global().unwrap_or_else(|e| {
            log::error!("Error during tainter initialization: {}", e);
            process::exit(FAILURE_EXIT_CODE);
        });
    })
}
