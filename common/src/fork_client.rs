// server: fuzzer/src/forsrv.rs
use crate::{
    afl_snapshot::{self, ConfigFlags},
    config,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use snafu::{ResultExt, Snafu};
use std::{
    io,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    ptr, result,
};

fn start_leaf_forksrv(
    socket_path: impl AsRef<Path>,
    mut socket: UnixStream,
    uses_snapshot: bool,
) -> Result<()> {
    let socket_path = socket_path.as_ref();

    let mut child_stopped = false;
    let mut child_pid = -1;
    loop {
        log::trace!("Waiting for new command: {}", socket_path.display());
        let command = socket
            .read_i32::<LittleEndian>()
            .context(TransmissionFailed)?;
        if command == 0 {
            log::debug!("Exiting fork server: {}", socket_path.display());
            if child_stopped {
                // If we are simply closing the fork server, kill the stopped child.
                unsafe { libc::kill(child_pid, libc::SIGKILL) };
            }

            return ShouldExit.fail();
        }

        if !child_stopped {
            log::trace!("Forking new child: {}", socket_path.display());
            child_pid = unsafe { libc::fork() };
            if child_pid == 0 {
                // Close socket to fuzzer before taking the snapshot.
                drop(socket);

                return continue_as_child(socket_path, uses_snapshot);
            }
        } else {
            assert!(child_pid > 0);
            log::trace!("Resuming stopped child: {}", socket_path.display());
            if unsafe { libc::kill(child_pid, libc::SIGCONT) } < 0 {
                return ResumeFailed.fail();
            }
            child_stopped = false;
        }

        // Communicate `fork` error (child_pid < 1) back to fuzzer as well.
        log::trace!(
            "Reporting new child PID for {}: {}",
            socket_path.display(),
            child_pid
        );
        socket
            .write_i32::<LittleEndian>(child_pid)
            .context(TransmissionFailed)?;

        if child_pid < 0 {
            log::warn!("Spawning child failed!");
            return SpawnFailed.fail();
        }

        log::trace!("Waiting for spawned child: {}", socket_path.display());

        let mut status = 0;
        if unsafe { libc::waitpid(child_pid, &mut status, libc::WUNTRACED) } < 0 {
            return WaitFailed.fail();
        }

        if libc::WIFSTOPPED(status) {
            child_stopped = true;
        }

        socket
            .write_i32::<LittleEndian>(status)
            .context(TransmissionFailed)?;
    }
}

fn continue_as_child(socket_path: impl AsRef<Path>, uses_snapshot: bool) -> Result<()> {
    if !uses_snapshot {
        return Ok(());
    }

    let socket_path = socket_path.as_ref();

    log::trace!("Taking process snapshot: {}", socket_path.display());
    if !afl_snapshot::take(
        ConfigFlags::MMAP | ConfigFlags::FDS | ConfigFlags::REGS | ConfigFlags::EXIT,
    ) {
        log::trace!("Snapshot resume, stopping: {}", socket_path.display());
        unsafe { libc::raise(libc::SIGSTOP) };
    } else {
        log::trace!("Snapshot taken, continuing: {}", socket_path.display());
    }

    Ok(())
}

fn start_intermediate_forksrv(socket_path: impl AsRef<Path>, mut socket: UnixStream) -> Result<()> {
    let socket_path = socket_path.as_ref();

    loop {
        log::trace!("Waiting for new command: {}", socket_path.display());
        let command = socket
            .read_i32::<LittleEndian>()
            .context(TransmissionFailed)?;
        if command == 0 {
            log::debug!("Cleaning up remaining children: {}", socket_path.display());
            wait_all_children(true);

            log::debug!("Exiting fork server: {}", socket_path.display());
            return ShouldExit.fail();
        }

        log::trace!("Forking new child: {}", socket_path.display());
        let child_pid = unsafe { libc::fork() };
        if child_pid == 0 {
            return Ok(());
        }

        // Communicate `fork` error (child_pid < 1) back to fuzzer as well.
        log::trace!(
            "Reporting new child PID for {}: {}",
            socket_path.display(),
            child_pid
        );
        socket
            .write_i32::<LittleEndian>(child_pid)
            .context(TransmissionFailed)?;

        if child_pid < 0 {
            log::warn!("Spawning child failed!");
            return SpawnFailed.fail();
        }

        wait_all_children(false);
    }
}

fn wait_all_children(should_block: bool) {
    loop {
        let wait_result = unsafe {
            libc::waitpid(
                -1,
                ptr::null_mut(),
                if should_block { 0 } else { libc::WNOHANG },
            )
        };

        if wait_result == 0 {
            log::trace!("No child has terminated yet");
            break;
        } else if wait_result < 0 {
            let error = io::Error::last_os_error();

            // It is fine if there are no children. We just want to make sure
            // that we are not leaving zombies around.
            if error.raw_os_error().unwrap() != libc::ECHILD {
                log::warn!("Error while waiting for remaining children: {}", error);
            }
            break;
        } else {
            log::trace!("Waited for child: {}", wait_result);
        }
    }
}

pub fn start(
    socket_path: impl AsRef<Path>,
    is_leaf_forksrv: bool,
    should_use_snapshot: bool,
) -> Result<()> {
    let socket = UnixStream::connect(socket_path.as_ref()).context(ConnectFailed {
        socket_path: socket_path.as_ref().to_path_buf(),
    })?;
    socket
        .set_write_timeout(Some(config::TIME_LIMIT_TRACK * 2))
        .expect("Timeout was 0");

    let uses_snapshot = if should_use_snapshot {
        if let Err(error) = afl_snapshot::init() {
            log::debug!("AFL snapshot init failed: {}", error);
            false
        } else {
            log::debug!("Using AFL snapshot");
            true
        }
    } else {
        log::debug!("AFL snapshot not requested");
        false
    };

    if is_leaf_forksrv {
        start_leaf_forksrv(socket_path, socket, uses_snapshot)
    } else {
        start_intermediate_forksrv(socket_path, socket)
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Could not connect to {}: {}", socket_path.display(), source))]
    ConnectFailed {
        socket_path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Could not send message to fuzzer: {}", source))]
    TransmissionFailed { source: io::Error },
    #[snafu(display("Could not spawn new child"))]
    SpawnFailed,
    #[snafu(display("Could not wait for child process"))]
    WaitFailed,
    #[snafu(display("Fork client should exit"))]
    ShouldExit,
    #[snafu(display("Could not restart stopped process"))]
    ResumeFailed,
}
