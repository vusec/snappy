use super::{
    ForkServerFailed, ForkServerShouldExit, Fuzzer, FuzzerInitFailed, FuzzerNotSupported,
    TestCaseError,
};

use angora_common::{defs, fork_client, shm, test_case::TestCase};
use once_cell::sync::OnceCell;
use runtime_fast::{context, shm_branches, shm_conds::ShmConds};
use snafu::{ResultExt, Snafu};
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    result,
    time::Instant,
};

static GLOBAL_STATE: OnceCell<GlobalState> = OnceCell::new();

#[derive(Debug)]
struct GlobalState {
    shared_test_case: shm::SHM<TestCase>,
}

// `shared_test_case` contains a pointer to a shared memory region. The
// instrumented binary never writes to it, only the fuzzer does and not when
// this binary is running.
unsafe impl Send for GlobalState {}
unsafe impl Sync for GlobalState {}

impl GlobalState {
    pub fn new() -> Result<Self> {
        let branches_shm_id = env::var(defs::BRANCHES_SHM_ENV_VAR).context(EnvVarNotSet {
            var_name: defs::BRANCHES_SHM_ENV_VAR.to_string(),
        })?;
        let branches_shm_id = branches_shm_id.parse::<i32>().context(ParseShmIDFailed {
            var_name: defs::BRANCHES_SHM_ENV_VAR.to_string(),
            var_value: branches_shm_id,
        })?;
        shm_branches::map_branch_counting_shm(branches_shm_id);

        let cond_stmt_shm_id = env::var(defs::COND_STMT_ENV_VAR).context(EnvVarNotSet {
            var_name: defs::COND_STMT_ENV_VAR.to_string(),
        })?;
        let cond_stmt_shm_id = cond_stmt_shm_id.parse::<i32>().context(ParseShmIDFailed {
            var_name: defs::COND_STMT_ENV_VAR.to_string(),
            var_value: cond_stmt_shm_id,
        })?;
        ShmConds::global_init(cond_stmt_shm_id);

        let test_case_shm_id = env::var(defs::TEST_CASE_SHM_ID_VARNAME).context(EnvVarNotSet {
            var_name: defs::TEST_CASE_SHM_ID_VARNAME.to_string(),
        })?;
        let test_case_shm_id = test_case_shm_id.parse::<i32>().context(ParseShmIDFailed {
            var_name: defs::TEST_CASE_SHM_ID_VARNAME.to_string(),
            var_value: test_case_shm_id,
        })?;
        let shared_test_case = shm::SHM::<TestCase>::from_id(test_case_shm_id);

        Ok(Self { shared_test_case })
    }

    /// Get a reference to the global state's shared test case.
    fn shared_test_case(&self) -> &shm::SHM<TestCase> {
        &self.shared_test_case
    }
}

pub struct Angora {
    socket_path: PathBuf,
    global_state: &'static OnceCell<GlobalState>,
}

impl Angora {
    pub fn new() -> super::Result<Self> {
        let dispatch_socket_path = if let Ok(socket_path) = env::var(defs::FORKSRV_SOCKET_PATH_VAR)
        {
            PathBuf::from(socket_path)
        } else {
            return FuzzerNotSupported.fail();
        };

        // Lazily initialize the global state if the fuzzer is selected.
        GLOBAL_STATE
            .get_or_try_init(GlobalState::new)
            .map_err(|error| {
                FuzzerInitFailed {
                    error: Box::new(error),
                }
                .build()
            })?;

        log::trace!(
            "Socket dispatch file path: {}",
            dispatch_socket_path.display()
        );
        let mut dispatch_socket_file = BufReader::new(
            File::open(dispatch_socket_path).expect("Could not open dispatch socket file"),
        );

        let mut socket_path = String::new();
        dispatch_socket_file
            .read_line(&mut socket_path)
            .expect("Could not read socket path");
        let socket_path: PathBuf = socket_path.trim_end().into();
        log::trace!("Socket path: {}", socket_path.display());

        Ok(Self {
            socket_path,
            global_state: &GLOBAL_STATE,
        })
    }
}

impl Fuzzer for Angora {
    fn snapshot(&self, is_leaf_forksrv: bool) -> super::Result<()> {
        let snapshot_context = context::get_context();
        log::debug!("Snapshotting with context: {}", snapshot_context);

        log::trace!("Connecting to fuzzer: {}", &self.socket_path.display());
        fork_client::start(&self.socket_path, is_leaf_forksrv, true).map_err(
            |error| match error {
                fork_client::Error::ShouldExit => ForkServerShouldExit.build(),
                error => ForkServerFailed {
                    error: Box::new(error),
                }
                .build(),
            },
        )?;

        let plugin_restore_begin = Instant::now();

        let mut cond_shm = ShmConds::global().unwrap();
        cond_shm.reset_target();

        let cond = cond_shm.cond();
        log::trace!(
            "Targeting condition (id: {}, ctx: {}, order: {})",
            cond.cmpid,
            cond.context,
            cond.order,
        );

        log::debug!("Plugin restore took: {:?}", plugin_restore_begin.elapsed());

        // The context has to remain the same before and after each delayed
        // snapshot otherwise there could be mismatches. The snapshot performed
        // in the constructor should always have context 0.
        assert_eq!(snapshot_context, context::get_context());

        Ok(())
    }

    fn get_byte_at_offset(&self, offset: usize) -> super::Result<u8> {
        self.global_state
            .get()
            .unwrap()
            .shared_test_case()
            .get_content_byte(offset)
            .map_err(|error| {
                TestCaseError {
                    error: Box::new(error),
                }
                .build()
            })
    }
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Could not use {}: {}", var_name, source))]
    EnvVarNotSet {
        var_name: String,
        source: std::env::VarError,
    },
    #[snafu(display("Could not parse {} as shared memory ID: {}", var_name, var_value))]
    ParseShmIDFailed {
        var_name: String,
        var_value: String,
        source: std::num::ParseIntError,
    },
}
