use snafu::Snafu;
use std::{error, result};

pub trait Fuzzer {
    fn snapshot(&self, is_leaf_forksrv: bool) -> Result<()>;
}

mod dummy;
use dummy::Dummy;

#[cfg(feature = "angora")]
mod angora;
#[cfg(feature = "angora")]
use angora::Angora;

pub fn build_fuzzer() -> Box<dyn Fuzzer + Send> {
    #[cfg(feature = "angora")]
    {
        if let Ok(angora) = Angora::new() {
            log::info!("Running with Angora fuzzer");
            return Box::new(angora);
        }
    }

    log::info!("Running with dummy fuzzer");
    Box::new(Dummy::new().unwrap())
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug, Snafu)]
pub enum Error {
    FuzzerNotSupported,
    #[snafu(display("Error in fork server: {}", error))]
    ForkServerFailed {
        error: Box<dyn error::Error>,
    },
}
