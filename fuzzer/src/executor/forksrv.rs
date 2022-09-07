use super::{
    limit::SetLimit,
    pollable::{PollEvents, Pollable},
    StatusType,
};
use angora_common::defs;

use anyhow::{anyhow, Context};
use byteorder::{LittleEndian, ReadBytesExt};
use libc;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::prelude::*,
    os::unix::{
        io::RawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

// Just meaningless value for forking a new child
static FORKSRV_NEW_CHILD: [u8; 4] = [8, 8, 8, 8];

/// This structure manages a fork server process. It allows to start it, reset it
/// when needed and spawn new children. It does not handle the input test case,
/// which needs to be set up before spawning new children.
#[derive(Debug)]
pub struct Forksrv {
    socket_path: PathBuf,
    socket: UnixStream,
    uses_asan: bool,
}

impl Forksrv {
    pub fn new(
        socket_path: impl AsRef<Path>,
        target: &(PathBuf, Vec<OsString>),
        envs: &HashMap<OsString, OsString>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
    ) -> Result<Forksrv, anyhow::Error> {
        debug!("socket_path: {:?}", socket_path.as_ref().display());
        let listener = UnixListener::bind(&socket_path).context("Failed to bind to socket")?;

        let mut envs_fk = envs.clone();
        envs_fk.insert(OsString::from(defs::ENABLE_FORKSRV), OsString::from("TRUE"));
        envs_fk.insert(
            OsString::from(defs::FORKSRV_SOCKET_PATH_VAR),
            socket_path.as_ref().into(),
        );
        Command::new(&target.0)
            .args(&target.1)
            .stdin(Stdio::null())
            .envs(&envs_fk)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .mem_limit(mem_limit)
            .block_core_files()
            .setsid()
            .pipe_stdin(fd, is_stdin)
            .spawn()
            .context("Failed to spawn child.")?;

        log::trace!(
            "Polling for connection request on: {}",
            socket_path.as_ref().display()
        );
        if !listener
            .poll(PollEvents::POLLIN, Some(time_limit))
            .context("Failed to poll on socket")?
        {
            return Err(anyhow!(
                "Child failed to connect to socket: {}",
                socket_path.as_ref().display()
            ));
        }

        log::trace!(
            "Accepting connection on: {}",
            socket_path.as_ref().display()
        );
        let (socket, _) = listener.accept().context("Failed to accept from socket")?;

        socket
            .set_read_timeout(Some(time_limit))
            .expect("Timeout was zero");
        socket
            .set_write_timeout(Some(time_limit))
            .expect("Timeout was zero");

        debug!(
            "All right -- Init ForkServer {} successfully!",
            socket_path.as_ref().display()
        );

        Ok(Forksrv {
            socket_path: socket_path.as_ref().to_path_buf(),
            socket,
            uses_asan,
        })
    }

    /// Spawn new child from fork server. The input for the target program should
    /// have already been modified appropriately, this function handles only the
    /// communication over the sockets.
    pub fn run(&mut self) -> StatusType {
        if self.socket.write(&FORKSRV_NEW_CHILD).is_err() {
            warn!("Fail to write socket!!");
            return StatusType::Error;
        }

        let mut buf = vec![0; 4];
        let child_pid: i32;
        match self.socket.read(&mut buf) {
            Ok(_) => {
                child_pid = match (&buf[..]).read_i32::<LittleEndian>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Unable to recover child pid: {:?}", e);
                        return StatusType::Error;
                    },
                };
                if child_pid <= 0 {
                    warn!(
                        "Unable to request new process from fork server! {}",
                        child_pid
                    );
                    return StatusType::Error;
                }
            },
            Err(error) => {
                warn!("Fail to read child_id -- {}", error);
                return StatusType::Error;
            },
        }

        buf = vec![0; 4];

        let read_result = self.socket.read(&mut buf);

        match read_result {
            Ok(_) => {
                let status = match (&buf[..]).read_i32::<LittleEndian>() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Unable to recover result from child: {}", e);
                        return StatusType::Error;
                    },
                };
                let exit_code = libc::WEXITSTATUS(status);
                let signaled = libc::WIFSIGNALED(status);
                if signaled || (self.uses_asan && exit_code == defs::MSAN_ERROR_CODE) {
                    debug!("Crash code: {}", status);
                    StatusType::Crash
                } else {
                    StatusType::Normal
                }
            },
            Err(_) => {
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                }
                let tmout_buf = &mut [0u8; 16];
                while let Err(_) = self.socket.read(tmout_buf) {
                    warn!("Killing timed out process");
                }
                return StatusType::Timeout;
            },
        }
    }
}

impl Drop for Forksrv {
    fn drop(&mut self) {
        debug!("Exit Forksrv");
        // Tell the child process to exit
        let fin = [0u8; 2];
        if self.socket.write(&fin).is_err() {
            debug!("Fail to write socket !!  FIN ");
        }
        if self.socket_path.exists() {
            if fs::remove_file(&self.socket_path).is_err() {
                warn!("Fail to remove socket file!!  FIN ");
            }
        }
    }
}
