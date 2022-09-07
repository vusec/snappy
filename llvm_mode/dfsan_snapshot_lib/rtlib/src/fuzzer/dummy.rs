use super::{Fuzzer, Result};

pub struct Dummy;

impl Dummy {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl Fuzzer for Dummy {
    fn snapshot(&self, _is_leaf_forksrv: bool) -> Result<()> {
        Ok(())
    }
}
