use std::{
    io,
    os::unix::{io::RawFd, process::CommandExt},
    process::Command,
};

pub trait SetLimit {
    fn mem_limit(&mut self, size: u64) -> &mut Self;
    fn block_core_files(&mut self) -> &mut Self;
    fn setsid(&mut self) -> &mut Self;
    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self;
}

impl SetLimit for Command {
    fn mem_limit(&mut self, size: u64) -> &mut Self {
        if size == 0 {
            return self;
        }

        let func = move || {
            let size = size << 20;
            let mem_limit: libc::rlim_t = size;

            let address_space_limit = libc::rlimit {
                rlim_cur: mem_limit,
                rlim_max: mem_limit,
            };

            if unsafe { libc::setrlimit(libc::RLIMIT_AS, &address_space_limit) } == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }

    fn block_core_files(&mut self) -> &mut Self {
        let func = move || {
            let core_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) } == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }

    fn setsid(&mut self) -> &mut Self {
        let func = move || {
            if unsafe { libc::setsid() } == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }

    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self {
        if !is_stdin {
            return self;
        }

        let func = move || {
            if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } == -1 {
                return Err(io::Error::last_os_error());
            }

            if unsafe { libc::close(fd) } == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }
}
