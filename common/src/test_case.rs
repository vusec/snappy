use snafu::{ensure, Snafu};

use crate::config;

#[repr(C)]
pub struct TestCase {
    content: [u8; config::TEST_CASE_SHM_SIZE],
    size: usize,
}

impl TestCase {
    pub fn set_content(&mut self, content: &[u8]) -> Result<(), TestCaseError> {
        ensure!(
            content.len() <= self.content.len(),
            TestCaseTooLong {
                length: content.len()
            }
        );

        self.size = content.len();
        for (dest_byte, src_byte) in self.content.iter_mut().zip(content) {
            *dest_byte = *src_byte;
        }

        Ok(())
    }

    pub fn get_content_byte(&self, offset: usize) -> Result<u8, TestCaseError> {
        ensure!(
            offset < self.size,
            IndexOutOfBounds {
                offset,
                current_length: self.size,
            }
        );
        Ok(self.content[offset])
    }
}

#[derive(Snafu, Debug)]
pub enum TestCaseError {
    #[snafu(display("Test case too long, it was {} bytes.", length))]
    TestCaseTooLong { length: usize },
    #[snafu(display(
        "Shared test case offset {} out of bounds [0,{}).",
        offset,
        current_length
    ))]
    IndexOutOfBounds {
        offset: usize,
        current_length: usize,
    },
}
