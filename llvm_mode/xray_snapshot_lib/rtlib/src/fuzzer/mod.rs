use snafu::Snafu;
use std::{error, result};

pub trait Fuzzer {
    fn snapshot(&self, is_leaf_forksrv: bool) -> Result<()>;
    fn get_byte_at_offset(&self, _offset: usize) -> Result<u8>;
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
    #[snafu(display("Error initializing fuzzer plugin: {}", error))]
    FuzzerInitFailed {
        error: Box<dyn error::Error>,
    },
    FuzzerNotSupported,
    ForkServerShouldExit,
    #[snafu(display("Error in fork server: {}", error))]
    ForkServerFailed {
        error: Box<dyn error::Error>,
    },
    #[snafu(display("Error interacting with the shared test case: {}", error))]
    TestCaseError {
        error: Box<dyn error::Error>,
    },
}
