use std::{io, os::unix::prelude::AsRawFd, time::Duration};

use bitflags::bitflags;

bitflags! {
    pub struct PollEvents: libc::c_short {
        const POLLIN = libc::POLLIN;
        const POLLOUT = libc::POLLOUT;
        const POLLERR = libc::POLLERR;
    }
}

pub trait Pollable: AsRawFd {
    /// Poll this pollable item for the `events` specified with an optional `timeout`.
    ///
    /// If a `timeout` is provided, the call will return `Ok(false)` when the
    /// timeout expires; if no `timeout` is provided, the call will block until
    /// an event occurs and then return `Ok(true)`.
    fn poll(&self, events: PollEvents, timeout: Option<Duration>) -> io::Result<bool> {
        let mut poll_item = libc::pollfd {
            fd: self.as_raw_fd(),
            events: events.bits(),
            revents: PollEvents::empty().bits(),
        };
        let timeout = if let Some(timeout) = timeout {
            timeout.as_millis() as libc::c_int
        } else {
            -1
        };

        let result = unsafe { libc::poll(&mut poll_item, 1, timeout) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(result > 0)
    }
}

impl<T: AsRawFd> Pollable for T {}
