use crate::tainter::Tainter;

use libc::{c_char, c_int, c_long, c_void, off_t, size_t, ssize_t, FILE};
use paste::paste;
use std::{cell::RefCell, ffi::CStr, os::unix::prelude::*};

macro_rules! safe_debug {
    ($($arg:tt)+) => (
        log::debug!($($arg)+);
    )
}

macro_rules! safe_warn {
    ($($arg:tt)+) => (
        log::warn!($($arg)+);
    )
}

thread_local! {
    static INSTRUMENTATION_ENABLED: RefCell<bool> = RefCell::new(true);
}

pub fn with_instrumentation_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let mut is_instrumentation_enabled = false;

    INSTRUMENTATION_ENABLED.with(|instrumentation_enabled| {
        let mut instrumentation_enabled = instrumentation_enabled.borrow_mut();
        is_instrumentation_enabled = *instrumentation_enabled;
        *instrumentation_enabled = false;
    });

    let ret = f();

    INSTRUMENTATION_ENABLED.with(|instrumentation_enabled| {
        let mut instrumentation_enabled = instrumentation_enabled.borrow_mut();
        *instrumentation_enabled = is_instrumentation_enabled;
    });

    ret
}

fn is_instrumentation_enabled() -> bool {
    INSTRUMENTATION_ENABLED.with(|instrumentation_enabled| *instrumentation_enabled.borrow())
}

macro_rules! define_wrapper {
    (fn $name:ident($($arg:ident:$type:ty),* $(,)?) $(-> $ret:ty)? $body:block) => {
        paste! {
            extern "C" {
                fn [<__real_ $name>]($($arg:$type),*) $(-> $ret)?;
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<__wrap_ $name>]($($arg:$type),*) $(-> $ret)? {
                if is_instrumentation_enabled() {
                    with_instrumentation_disabled(|| $body)
                } else {
                    [<__real_ $name>]($($arg),*)
                }
            }
        }
    }
}

macro_rules! define_redirect {
    (fn $name:ident($($arg:ident:$type:ty),* $(,)?) $(-> $ret:ty)? $body:block) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<__wrap_ $name>]($($arg:$type),*) $(-> $ret)? $body
        }
    }
}

extern "C" {
    fn __real_open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap_open(path: *const c_char, oflag: c_int, mut arg: ...) -> c_int {
    let mode = if open_needs_mode(oflag) { arg.arg() } else { 0 };

    if !is_instrumentation_enabled() {
        return __real_open(path, oflag, mode);
    }

    with_instrumentation_disabled(|| {
        safe_debug!("Wrapper called: {}", "open");

        let fd = __real_open(path, oflag, mode);
        if fd == -1 {
            // open failed
            return fd;
        }

        // We can only trust the calling program, no check can be performed
        let path_str = if let Ok(path_str) = CStr::from_ptr(path).to_str() {
            path_str
        } else {
            safe_warn!("Could not convert path to UTF-8");
            return fd;
        };

        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return fd;
        };

        tainter.trace_open_fd(fd, path_str);

        fd
    })
}

fn open_needs_mode(oflag: c_int) -> bool {
    // This definition is taken from "fcntl.h"
    oflag & libc::O_CREAT != 0 || oflag & libc::O_TMPFILE == libc::O_TMPFILE
}

define_wrapper!(
    fn fopen(filename: *const c_char, mode: *const c_char) -> *mut FILE {
        safe_debug!("Wrapper called: {}", "fopen");

        let file = __real_fopen(filename, mode);
        if file.is_null() {
            // fopen failed
            return file;
        }

        // We can only trust the calling program, no check can be performed
        let filename_str = if let Ok(filename_str) = CStr::from_ptr(filename).to_str() {
            filename_str
        } else {
            safe_warn!("Could not convert path to UTF-8");
            return file;
        };

        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return file;
        };

        // fileno fails only if file is not a valid stream, checked before
        tainter.trace_open_file(file, filename_str);

        file
    }
);

define_redirect!(
    fn fopen64(filename: *const c_char, mode: *const c_char) -> *mut FILE {
        // On x86_64 it is a simple redirect
        safe_debug!("Redirect from: {}", "fopen64");
        __wrap_fopen(filename, mode)
    }
);

define_wrapper!(
    fn freopen(filename: *const c_char, mode: *const c_char, stream: *mut FILE) -> *mut FILE {
        safe_debug!("Wrapper called: {}", "freopen");

        let file = __real_freopen(filename, mode, stream);
        if file.is_null() {
            // freopen failed
            return file;
        }

        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return file;
        };

        tainter.trace_close_file(stream);

        // We can only trust the calling program, no check can be performed
        let filename_str = if let Ok(filename_str) = CStr::from_ptr(filename).to_str() {
            filename_str
        } else {
            safe_warn!("Could not convert path to UTF-8");
            return file;
        };

        // fileno fails only if file is not a valid stream, checked before
        tainter.trace_open_file(file, filename_str);

        file
    }
);

define_redirect!(
    fn freopen64(filename: *const c_char, mode: *const c_char, stream: *mut FILE) -> *mut FILE {
        safe_debug!("Redirect from: {}", "freopen64");
        __wrap_freopen(filename, mode, stream)
    }
);

define_wrapper!(
    fn close(fd: c_int) -> c_int {
        safe_debug!("Wrapper called: {}", "close");

        let ret = __real_close(fd);
        if ret == -1 {
            // close failed
            return ret;
        }

        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return ret;
        };

        tainter.trace_close_fd(fd);

        ret
    }
);

define_wrapper!(
    fn fclose(file: *mut FILE) -> c_int {
        safe_debug!("Wrapper called: {}", "fclose");

        let ret = __real_fclose(file);
        if ret == libc::EOF {
            // fclose failed
            return ret;
        }

        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return ret;
        };

        tainter.trace_close_file(file);

        ret
    }
);

fn maybe_trace_read_fd(fd: RawFd) {
    if let Some(mut tainter) = Tainter::global() {
        tainter.trace_read_attempt_fd(fd);
    } else {
        safe_warn!("Tainter not initialized");
    };
}

fn maybe_trace_read_file(file: *mut FILE) {
    if let Some(mut tainter) = Tainter::global() {
        tainter.trace_read_attempt_file(file);
    } else {
        safe_warn!("Tainter not initialized");
    };
}

define_wrapper!(
    fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void {
        safe_debug!("Wrapper called: {}", "mmap");

        if flags & libc::MAP_ANONYMOUS == 0 {
            maybe_trace_read_fd(fd);
        }

        __real_mmap(addr, len, prot, flags, fd, offset)
    }
);

define_wrapper!(
    fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
        safe_debug!("Wrapper called: {}", "read");
        maybe_trace_read_fd(fd);
        __real_read(fd, buf, count)
    }
);

define_wrapper!(
    fn pread(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
        safe_debug!("Wrapper called: {}", "pread");
        maybe_trace_read_fd(fd);
        __real_pread(fd, buf, count, offset)
    }
);

define_wrapper!(
    fn fread(ptr: *mut c_void, size: size_t, nobj: size_t, stream: *mut FILE) -> size_t {
        safe_debug!("Wrapper called: {}", "fread");
        maybe_trace_read_file(stream);
        __real_fread(ptr, size, nobj, stream)
    }
);

// Not in POSIX standard
define_wrapper!(
    fn fread_unlocked(ptr: *mut c_void, size: size_t, nobj: size_t, stream: *mut FILE) -> size_t {
        safe_debug!("Wrapper called: {}", "fread_unlocked");
        maybe_trace_read_file(stream);
        __real_fread_unlocked(ptr, size, nobj, stream)
    }
);

define_wrapper!(
    fn fgetc(stream: *mut FILE) -> c_int {
        safe_debug!("Wrapper called: {}", "fgetc");
        maybe_trace_read_file(stream);
        __real_fgetc(stream)
    }
);

// Not in POSIX standard
define_redirect!(
    fn fgetc_unlocked(stream: *mut FILE) -> c_int {
        safe_debug!("Redirect from: {}", "fgetc_unlocked");
        __wrap_getc_unlocked(stream)
    }
);

define_redirect!(
    fn getc(stream: *mut FILE) -> c_int {
        safe_debug!("Redirect from: {}", "getc");
        __wrap_fgetc(stream)
    }
);

define_wrapper!(
    fn getc_unlocked(stream: *mut FILE) -> c_int {
        safe_debug!("Wrapper called: {}", "getc_unlocked");
        maybe_trace_read_file(stream);
        __real_getc_unlocked(stream)
    }
);

define_wrapper!(
    fn fgets(buf: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char {
        safe_debug!("Wrapper called: {}", "fgets");
        maybe_trace_read_file(stream);
        __real_fgets(buf, n, stream)
    }
);

// Not in POSIX standard
define_wrapper!(
    fn fgets_unlocked(buf: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char {
        safe_debug!("Wrapper called: {}", "fgets_unlocked");
        maybe_trace_read_file(stream);
        __real_fgets_unlocked(buf, n, stream)
    }
);

define_wrapper!(
    fn getline(lineptr: *mut *mut c_char, n: *mut size_t, stream: *mut FILE) -> ssize_t {
        safe_debug!("Wrapper called: {}", "getline");
        maybe_trace_read_file(stream);
        __real_getline(lineptr, n, stream)
    }
);

define_wrapper!(
    fn getdelim(
        lineptr: *mut *mut c_char,
        n: *mut size_t,
        delim: c_int,
        stream: *mut FILE,
    ) -> ssize_t {
        safe_debug!("Wrapper called: {}", "getdelim");
        maybe_trace_read_file(stream);
        __real_getdelim(lineptr, n, delim, stream)
    }
);

define_wrapper!(
    fn vfscanf(stream: *mut FILE, format: *const c_char, ap: std::ffi::VaList) -> c_int {
        safe_debug!("Wrapper called: {}", "vfscanf");
        maybe_trace_read_file(stream);
        __real_vfscanf(stream, format, ap)
    }
);

#[no_mangle]
pub unsafe extern "C" fn __wrap_fscanf(
    stream: *mut FILE,
    format: *const c_char,
    mut arg: ...
) -> c_int {
    if !is_instrumentation_enabled() {
        return __real_vfscanf(stream, format, arg.as_va_list());
    }

    with_instrumentation_disabled(|| {
        safe_debug!("Wrapper called: {}", "fscanf");
        maybe_trace_read_file(stream);
        __real_vfscanf(stream, format, arg.as_va_list())
    })
}

unsafe fn maybe_trace_size_check_by_name(pathname: *const c_char) {
    // We can only trust the calling program, no check can be performed
    let path_str = if let Ok(path_str) = CStr::from_ptr(pathname).to_str() {
        path_str
    } else {
        safe_warn!("Could not convert path to UTF-8");
        return;
    };

    if let Some(mut tainter) = Tainter::global() {
        tainter.trace_size_check_by_name(path_str);
    } else {
        safe_warn!("Tainter not initialized");
    };
}

define_wrapper!(
    fn stat(pathname: *const c_char, statbuf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "stat");
        maybe_trace_size_check_by_name(pathname);
        __real_stat(pathname, statbuf)
    }
);

define_wrapper!(
    fn __xstat(ver: c_int, path: *const c_char, stat_buf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "__xstat");
        maybe_trace_size_check_by_name(path);
        __real___xstat(ver, path, stat_buf)
    }
);

define_wrapper!(
    fn fstat(fd: c_int, statbuf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "fstat");
        if let Some(mut tainter) = Tainter::global() {
            tainter.trace_size_check_fd(fd);
        } else {
            safe_warn!("Tainter not initialized");
        };
        __real_fstat(fd, statbuf)
    }
);

define_wrapper!(
    fn __fxstat(ver: c_int, fildes: c_int, stat_buf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "__fxstat");
        if let Some(mut tainter) = Tainter::global() {
            tainter.trace_size_check_fd(fildes);
        } else {
            safe_warn!("Tainter not initialized");
        };
        __real___fxstat(ver, fildes, stat_buf)
    }
);

define_wrapper!(
    fn lstat(pathname: *const c_char, statbuf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "lstat");
        maybe_trace_size_check_by_name(pathname);
        __real_lstat(pathname, statbuf)
    }
);

define_wrapper!(
    fn __lxstat(ver: c_int, path: *const c_char, stat_buf: *mut libc::stat) -> c_int {
        safe_debug!("Wrapper called: {}", "__lxstat");
        maybe_trace_size_check_by_name(path);
        __real___lxstat(ver, path, stat_buf)
    }
);

fn maybe_trace_size_file(file: *mut FILE) {
    if let Some(mut tainter) = Tainter::global() {
        tainter.trace_size_check_file(file);
    } else {
        safe_warn!("Tainter not initialized");
    };
}

define_wrapper!(
    fn ftell(stream: *mut FILE) -> c_long {
        safe_debug!("Wrapper called: {}", "ftell");
        maybe_trace_size_file(stream);
        __real_ftell(stream)
    }
);

define_wrapper!(
    fn fseek(stream: *mut FILE, offset: c_long, whence: c_int) -> c_int {
        safe_debug!("Wrapper called: {}", "fseek");
        maybe_trace_size_file(stream);
        __real_fseek(stream, offset, whence)
    }
);
