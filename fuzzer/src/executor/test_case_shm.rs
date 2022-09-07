use angora_common::{shm, test_case::TestCase};

pub struct TestCaseShm {
    shared_mem: shm::SHM<TestCase>,
}

impl TestCaseShm {
    pub fn new() -> Self {
        Self {
            shared_mem: shm::SHM::<TestCase>::new(),
        }
    }

    pub fn get_id(&self) -> i32 {
        self.shared_mem.get_id()
    }

    pub fn set_content(&mut self, content: &[u8]) -> anyhow::Result<()> {
        self.shared_mem.set_content(content)?;
        Ok(())
    }
}
