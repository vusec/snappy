use super::{ForkServerFailed, Fuzzer, FuzzerNotSupported, Result};

use angora_common::{defs, fork_client};
use std::{env, path::PathBuf, process};

pub struct Angora {
    socket_path: PathBuf,
}

unsafe impl Send for Angora {}

impl Angora {
    pub fn new() -> Result<Self> {
        let socket_path = if let Ok(socket_path) = env::var(defs::FORKSRV_SOCKET_PATH_VAR) {
            PathBuf::from(socket_path)
        } else {
            return FuzzerNotSupported.fail();
        };

        Ok(Self { socket_path })
    }
}

impl Fuzzer for Angora {
    fn snapshot(&self, is_leaf_forksrv: bool) -> Result<()> {
        fork_client::start(&self.socket_path, is_leaf_forksrv, true).map_err(|error| match error {
            fork_client::Error::ShouldExit => process::exit(0),
            error => ForkServerFailed {
                error: Box::new(error),
            }
            .build(),
        })
    }
}
