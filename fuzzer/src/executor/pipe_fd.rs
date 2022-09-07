use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom},
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
};

/// Structure used to manage the file in which new test cases for the program
/// under test are written.
pub struct PipeFd {
    file: File,
}

impl PipeFd {
    /// Open or create a file at `file_name`.
    pub fn new(file_name: impl AsRef<Path>) -> Self {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_name)
            .expect("Fail to open default input file!");

        Self { file: f }
    }

    /// Get raw file descriptor for file
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Replace the content of the file with `buf`.
    pub fn write_buf(&mut self, buf: &[u8]) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
        self.file.write_all(buf).unwrap();
        self.file.set_len(buf.len() as u64).unwrap();
        self.file.flush().unwrap();
        // f.sync_all().unwrap();
    }

    /// Seek to the start of the file (used only with stdin)
    pub fn rewind(&mut self) {
        self.file.seek(SeekFrom::Start(0)).unwrap();
    }
}
