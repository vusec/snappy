use crate::shm_conds::ShmConds;
use angora_common::fork_client;
use libc::{c_long, FILE};
use once_cell::sync::OnceCell;
use snafu::{ensure, ResultExt, Snafu};
use std::{
    collections::BTreeSet,
    io,
    os::unix::prelude::*,
    path::{Path, PathBuf},
    process,
    sync::{Mutex, MutexGuard},
};

static TAINTER: OnceCell<Mutex<Tainter>> = OnceCell::new();

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
struct FilePtr(*mut FILE);

// All the synchronous functions used to manipulate `FILE` structs are thread
// safe.
unsafe impl Send for FilePtr {}

impl From<*mut FILE> for FilePtr {
    fn from(file: *mut FILE) -> Self {
        Self(file)
    }
}

impl From<FilePtr> for *mut FILE {
    fn from(ptr: FilePtr) -> Self {
        ptr.0
    }
}

#[derive(Default)]
pub struct Tainter {
    forkserver_socket_path: Option<PathBuf>,

    canonical_tainted_path: Option<PathBuf>,
    tainted_file_descriptors: BTreeSet<RawFd>,
    tainted_file_structs: BTreeSet<FilePtr>,
    started_forkserver: bool,
}

impl Tainter {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        let lock = TAINTER.get()?;
        Some(lock.lock().unwrap())
    }

    fn should_taint_file(&self, current_path: impl AsRef<Path>) -> bool {
        let canonical_tainted_path =
            if let Some(tainted_path) = self.canonical_tainted_path.as_ref() {
                tainted_path
            } else {
                // Instrumentation disabled
                return false;
            };

        // Canonicalize may fail. In that case, ignore the error, open should have failed anyway.
        let canonical_current_path =
            if let Ok(canonical_current_path) = current_path.as_ref().canonicalize() {
                canonical_current_path
            } else {
                return false;
            };

        if canonical_tainted_path == &canonical_current_path {
            log::debug!(
                "Matching file detected: {}",
                canonical_current_path.display()
            );
            true
        } else {
            false
        }
    }

    pub fn trace_open_fd(&mut self, fd: RawFd, current_path: impl AsRef<Path>) {
        if self.should_taint_file(current_path) {
            assert!(fd >= 0);
            log::debug!("File descriptor: {}", fd);
            self.tainted_file_descriptors.insert(fd);
        }
    }

    pub fn trace_open_file(&mut self, file: *mut FILE, current_path: impl AsRef<Path>) {
        if self.should_taint_file(current_path) {
            assert!(!file.is_null());
            log::debug!("File struct: {:?}", file);
            self.tainted_file_structs.insert(file.into());
        }
    }

    fn record_fd_offsets(fds: &[RawFd]) -> Vec<usize> {
        fds.iter()
            .map(|fd| {
                let pos = unsafe { libc::lseek(*fd, 0, libc::SEEK_CUR) };
                if pos != -1 {
                    pos as usize
                } else {
                    panic!(
                        "Could not find offset for fd {}: {}",
                        *fd,
                        io::Error::last_os_error()
                    );
                }
            })
            .collect()
    }

    fn restore_fd_offsets(fds: &[RawFd], positions: &[usize]) {
        for (fd, pos) in fds.iter().zip(positions) {
            log::trace!("Seeking file descriptor {} to {}", *fd, *pos);

            let pos = unsafe { libc::lseek(*fd, *pos as libc::off_t, libc::SEEK_SET) };
            if pos == -1 {
                panic!(
                    "Could not reset offset for fd {}: {}",
                    *fd,
                    io::Error::last_os_error()
                );
            }
        }
    }

    fn record_file_offsets(files: &[FilePtr]) -> Vec<usize> {
        files
            .iter()
            .map(|file| unsafe {
                let pos = libc::ftell((*file).into());
                if pos != -1 {
                    pos as usize
                } else {
                    panic!(
                        "Could not find offset for file struct {:?}: {}",
                        *file,
                        io::Error::last_os_error()
                    );
                }
            })
            .collect()
    }

    fn restore_file_offsets(files: &[FilePtr], positions: &[usize]) {
        for (file, pos) in files.iter().zip(positions) {
            log::trace!("Seeking file struct {:?} to {}", *file, *pos);

            let pos = unsafe { libc::fseek((*file).into(), *pos as c_long, libc::SEEK_SET) };
            if pos == -1 {
                panic!(
                    "Could not reset offset for file struct {:?}: {}",
                    *file,
                    io::Error::last_os_error()
                );
            }

            let res = unsafe { libc::fflush((*file).into()) };
            if res == libc::EOF {
                panic!(
                    "Could not flush file struct {:?}: {}",
                    *file,
                    io::Error::last_os_error()
                );
            }
        }
    }

    fn start_fork_server(&mut self) {
        assert!(!self.started_forkserver);
        log::info!("Starting fork server");

        self.started_forkserver = true;

        let socket_path = if let Some(socket_path) = self.forkserver_socket_path.as_ref() {
            socket_path
        } else {
            log::info!("Fork server path not provided, performing a normal run");
            return;
        };

        let fds = self
            .tainted_file_descriptors
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let fd_positions = Self::record_fd_offsets(&fds);

        log::debug!("file descr: {:?}", fds);
        log::debug!("positions:  {:?}", fd_positions);

        let files = self
            .tainted_file_structs
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let file_positions = Self::record_file_offsets(&files);

        log::debug!("file structs: {:?}", files);
        log::debug!("positions:    {:?}", file_positions);

        fork_client::start(socket_path, true, true).unwrap_or_else(|error| match error {
            fork_client::Error::ShouldExit => process::exit(0),
            _ => {
                log::error!("Error in fork server: {}", error);
                process::exit(1);
            },
        });

        Self::restore_fd_offsets(&fds, &fd_positions);
        Self::restore_file_offsets(&files, &file_positions);

        // Run by spawned children
        ShmConds::global().unwrap().reset_target();
    }

    pub fn trace_read_attempt_fd(&mut self, file_descriptor: RawFd) {
        if !self.tainted_file_descriptors.contains(&file_descriptor) {
            // Not target file
            return;
        }

        log::debug!("File descriptor matched: {}", file_descriptor);

        if !self.started_forkserver {
            self.start_fork_server();
        } else {
            log::debug!("Forkserver already started");
        }
    }

    pub fn trace_read_attempt_file(&mut self, file: *mut FILE) {
        if !self.tainted_file_structs.contains(&file.into()) {
            // Not target file
            return;
        }

        log::debug!("File struct matched: {:?}", file);

        if !self.started_forkserver {
            self.start_fork_server();
        } else {
            log::debug!("Forkserver already started");
        }
    }

    pub fn trace_size_check_fd(&mut self, file_descriptor: RawFd) {
        if !self.tainted_file_descriptors.contains(&file_descriptor) {
            // Not target file
            return;
        }

        log::debug!("File descriptor matched: {}", file_descriptor);

        if !self.started_forkserver {
            self.start_fork_server();
        } else {
            log::debug!("Forkserver already started");
        }
    }

    pub fn trace_size_check_file(&mut self, file: *mut FILE) {
        if !self.tainted_file_structs.contains(&file.into()) {
            // Not target file
            return;
        }

        log::debug!("File struct matched: {:?}", file);

        if !self.started_forkserver {
            self.start_fork_server();
        } else {
            log::debug!("Forkserver already started");
        }
    }

    pub fn trace_size_check_by_name(&mut self, current_path: impl AsRef<Path>) {
        if !self.should_taint_file(&current_path) {
            // Not target file
            return;
        }

        log::debug!("Target file matched: {}", current_path.as_ref().display());

        if !self.started_forkserver {
            self.start_fork_server();
        } else {
            log::debug!("Forkserver already started");
        }
    }

    pub fn trace_close_fd(&mut self, fd: RawFd) {
        if self.tainted_file_descriptors.remove(&fd) {
            log::debug!("Removed file descriptor: {}", fd);
        }
    }

    pub fn trace_close_file(&mut self, file: *mut FILE) {
        if self.tainted_file_structs.remove(&file.into()) {
            log::debug!("Removed file struct: {:?}", file);
        }
    }
}

#[derive(Default)]
pub struct TainterBuilder {
    forkserver_socket_path: Option<PathBuf>,
    tainted_path: Option<PathBuf>,
}

impl TainterBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn forkserver_socket_path(&mut self, forkserver_socket_path: PathBuf) -> &mut Self {
        self.forkserver_socket_path = Some(forkserver_socket_path);
        self
    }

    pub fn tainted_file_path(&mut self, file_path: PathBuf) -> &mut Self {
        self.tainted_path = Some(file_path);
        self
    }

    pub fn build_global(self) -> Result<(), TainterError> {
        let canonical_path_opt = if let Some(tainted_path) = self.tainted_path {
            let canonical_path = tainted_path
                .canonicalize()
                .context(InvalidTaintPath { path: tainted_path })?;
            log::info!("Tainted file: {}", canonical_path.display());
            Some(canonical_path)
        } else {
            log::info!("No tainted file, instrumentation disabled");
            None
        };

        let tainter = Tainter {
            canonical_tainted_path: canonical_path_opt,
            forkserver_socket_path: self.forkserver_socket_path,
            ..Default::default()
        };

        ensure!(TAINTER.set(Mutex::new(tainter)).is_ok(), AlreadyExists);

        Ok(())
    }
}

#[derive(Debug, Snafu)]
pub enum TainterError {
    #[snafu(display("Cannot canonicalize tainted file path {}: {}", path.display(), source))]
    InvalidTaintPath {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Tainter has already been instantiated"))]
    AlreadyExists,
}
