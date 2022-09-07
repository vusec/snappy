use crate::{
    callbacks::trigger_tracer,
    dfsan::{dfsan_label, dfsan_read_label, dfsan_set_label},
    heap_tracer,
    tainter::Tainter,
};
use libc::{
    c_char, c_double, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void, off_t, size_t,
    ssize_t, FILE,
};
use std::{
    cmp::min,
    ffi::{CStr, VaList},
    ptr,
};

macro_rules! safe_debug {
    ($($arg:tt)+) => (
        if log::log_enabled!(log::Level::Debug) {
            heap_tracer::with_tracer_disabled(|| {
                log::log!(log::Level::Debug, $($arg)+);
            })
        }
    )
}

macro_rules! safe_warn {
    ($($arg:tt)+) => (
        if log::log_enabled!(log::Level::Warn) {
            heap_tracer::with_tracer_disabled(|| {
                log::log!(log::Level::Warn, $($arg)+);
            })
        }
    )
}

#[link(name = "c")]
extern "C" {
    // POSIX functions that are not present in libc crate
    fn getc_unlocked(stream: *mut FILE) -> c_int;
    fn getdelim(
        lineptr: *mut *mut c_char,
        n: *mut size_t,
        delim: c_int,
        stream: *mut FILE,
    ) -> ssize_t;

    // Non-POSIX function that is not preset in libc crate
    fn fgets_unlocked(buf: *mut c_char, n: c_int, stream: *mut FILE) -> *mut c_char;
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_open(
    path: *const c_char,
    oflag: c_int,
    _path_label: dfsan_label,
    _oflag_label: dfsan_label,
    ret_label: *mut dfsan_label,
    mut arg: ...
) -> c_int {
    safe_debug!("Wrapper called: {}", "open");
    *ret_label = 0;

    let mode = if open_needs_mode(oflag) { arg.arg() } else { 0 };
    let fd = libc::open(path, oflag, mode);
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

    tainter.trace_open(fd, path_str);

    fd
}

fn open_needs_mode(oflag: c_int) -> bool {
    // This definition is taken from "fcntl.h"
    oflag & libc::O_CREAT != 0 || oflag & libc::O_TMPFILE == libc::O_TMPFILE
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_fopen(
    filename: *const c_char,
    mode: *const c_char,
    _filename_label: dfsan_label,
    _mode_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut FILE {
    safe_debug!("Wrapper called: {}", "fopen");
    *ret_label = 0;

    let file = libc::fopen(filename, mode);
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
    tainter.trace_open(libc::fileno(file), filename_str);

    file
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_fopen64(
    filename: *const c_char,
    mode: *const c_char,
    filename_label: dfsan_label,
    mode_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut FILE {
    // On x86_64 it is a simple redirect
    safe_debug!("Redirect from: {}", "fopen64");
    __dfsw_fopen(filename, mode, filename_label, mode_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_close(
    fd: c_int,
    _fd_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Wrapper called: {}", "close");
    *ret_label = 0;

    let ret = libc::close(fd);
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

    tainter.trace_close(fd);

    ret
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_fclose(
    file: *mut FILE,
    _file_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Wrapper called: {}", "fclose");
    *ret_label = 0;

    let fd = libc::fileno(file); // Accessing FILE after fclose is UB

    let ret = libc::fclose(file);
    if ret == libc::EOF {
        // fclose failed
        return ret;
    }
    assert!(fd != -1); // fclose should have failed if file is not valid

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return ret;
    };

    tainter.trace_close(fd);

    ret
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_mmap(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
    _addr_label: dfsan_label,
    _len_label: dfsan_label,
    _prot_label: dfsan_label,
    _flags_label: dfsan_label,
    _fd_label: dfsan_label,
    _offset_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_void {
    safe_debug!("Wrapper called: {}", "mmap");
    *ret_label = 0;

    let addr_ret = libc::mmap(addr, len, prot, flags, fd, offset);
    if addr_ret == libc::MAP_FAILED {
        // mmap failed
        return addr_ret;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return addr_ret;
    };

    assert!(offset >= 0); // mmap fails with a negative offset
    tainter.trace_read(fd, addr_ret, offset as usize, len);

    addr_ret
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_munmap(
    addr: *mut c_void,
    len: size_t,
    _addr_label: dfsan_label,
    _len_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Wrapper called: {}", "munmap");
    *ret_label = 0;

    let ret = libc::munmap(addr, len);
    if ret < 0 {
        // munmap failed
        return ret;
    }

    // In theory the conversion could fail, so panic if it does
    dfsan_set_label(0, addr, len);

    ret
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_read(
    fd: c_int,
    buf: *mut c_void,
    count: size_t,
    _fd_label: dfsan_label,
    _buf_label: dfsan_label,
    _count_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> ssize_t {
    safe_debug!("Wrapper called: {}", "read");
    *ret_label = 0;

    let offset = libc::lseek(fd, 0, libc::SEEK_CUR);

    let bytes_read = libc::read(fd, buf, count);
    if bytes_read <= 0 {
        // No read occurred
        return bytes_read;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return bytes_read;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return bytes_read;
    };

    // offset and bytes_read are both positive
    tainter.trace_read(fd, buf, offset as usize, bytes_read as usize);

    bytes_read
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_pread(
    fd: c_int,
    buf: *mut c_void,
    count: size_t,
    offset: off_t,
    _fd_label: dfsan_label,
    _buf_label: dfsan_label,
    _count_label: dfsan_label,
    _offset_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> ssize_t {
    safe_debug!("Wrapper called: {}", "pread");
    *ret_label = 0;

    let bytes_read = libc::pread(fd, buf, count, offset);
    if bytes_read <= 0 {
        // No read occurred
        return bytes_read;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return bytes_read;
    };

    // offset and bytes_read are both positive
    tainter.trace_read(fd, buf, offset as usize, bytes_read as usize);

    bytes_read
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_fread(
    ptr: *mut c_void,
    size: size_t,
    nobj: size_t,
    stream: *mut FILE,
    _ptr_label: dfsan_label,
    _size_label: dfsan_label,
    _nobj_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> size_t {
    safe_debug!("Wrapper called: {}", "fread");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let count = libc::fread(ptr, size, nobj, stream);
    if count == 0 {
        // No read occurred
        return count;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return count;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return count;
    };

    let bytes_read = if let Some(bytes_read) = count.checked_mul(size) {
        bytes_read
    } else {
        safe_debug!("Overflow check failed");
        return count;
    };

    // stream is valid, otherwise fread would have failed
    // offset is positive, checked before
    tainter.trace_read(libc::fileno(stream), ptr, offset as usize, bytes_read);

    count
}

// Not in POSIX standard
#[no_mangle]
pub unsafe extern "C" fn __dfsw_fread_unlocked(
    ptr: *mut c_void,
    size: size_t,
    nobj: size_t,
    stream: *mut FILE,
    _ptr_label: dfsan_label,
    _size_label: dfsan_label,
    _nobj_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> size_t {
    safe_debug!("Wrapper called: {}", "fread_unlocked");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let count = libc::fread_unlocked(ptr, size, nobj, stream);
    if count == 0 {
        // No read occurred
        return count;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return count;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return count;
    };

    let bytes_read = if let Some(bytes_read) = count.checked_mul(size) {
        bytes_read
    } else {
        safe_debug!("Overflow check failed");
        return count;
    };

    // stream is valid, otherwise fread would have failed
    // offset is positive, checked before
    tainter.trace_read(libc::fileno(stream), ptr, offset as usize, bytes_read);

    count
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_fgetc(
    stream: *mut FILE,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Wrapper called: {}", "fgetc");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let c = libc::fgetc(stream);
    if c == libc::EOF {
        // Read failed
        return c;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return c;
    }

    let mut should_trigger_tracer = false;
    {
        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return c;
        };

        // offset is guaranteed to be positive at this point
        if let Some(byte_label) = tainter.get_byte_label(libc::fileno(stream), offset as usize) {
            *ret_label = byte_label;
            should_trigger_tracer = true;
        }
    }

    if should_trigger_tracer {
        trigger_tracer(); // fgetc implies a load of tainted data from memory
        unreachable!();
    }

    c
}

// Not in POSIX standard
#[no_mangle]
pub unsafe extern "C" fn __dfsw_fgetc_unlocked(
    stream: *mut FILE,
    stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Redirect from: {}", "fgetc_unlocked");
    __dfsw_getc_unlocked(stream, stream_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_getc(
    stream: *mut FILE,
    stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Redirect from: {}", "getc");
    __dfsw_fgetc(stream, stream_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_getc_unlocked(
    stream: *mut FILE,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    safe_debug!("Wrapper called: {}", "getc_unlocked");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let c = getc_unlocked(stream);
    if c == libc::EOF {
        // Read failed
        return c;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return c;
    }

    let mut should_trigger_tracer = false;
    {
        let mut tainter = if let Some(tainter) = Tainter::global() {
            tainter
        } else {
            safe_warn!("Tainter not initialized");
            return c;
        };

        // offset is guaranteed to be positive at this point
        if let Some(byte_label) = tainter.get_byte_label(libc::fileno(stream), offset as usize) {
            *ret_label = byte_label;
            should_trigger_tracer = true;
        }
    }

    if should_trigger_tracer {
        trigger_tracer(); // getc_unlocked implies a load of tainted data from memory
        unreachable!();
    }

    c
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_fgets(
    buf: *mut c_char,
    n: c_int,
    stream: *mut FILE,
    buf_label: dfsan_label,
    _n_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_char {
    safe_debug!("Wrapper called: {}", "fgets");

    let offset = libc::ftell(stream);

    let buf_ret = libc::fgets(buf, n, stream);
    if buf_ret.is_null() {
        // Read failed
        *ret_label = 0;
        return buf_ret;
    } else {
        *ret_label = buf_label;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return buf_ret;
    }

    // fgets is guaranteed to append a \0 if it succeeds
    let bytes_read = libc::strlen(buf);

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return buf_ret;
    };

    // stream is valid, otherwise fgets would have failed
    // offset is positive, checked before
    tainter.trace_read(
        libc::fileno(stream),
        buf.cast(),
        offset as usize,
        bytes_read,
    );

    buf_ret
}

// Not in POSIX standard
#[no_mangle]
pub unsafe extern "C" fn __dfsw_fgets_unlocked(
    buf: *mut c_char,
    n: c_int,
    stream: *mut FILE,
    buf_label: dfsan_label,
    _n_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_char {
    safe_debug!("Wrapper called: {}", "fgets_unlocked");

    let offset = libc::ftell(stream);

    let buf_ret = fgets_unlocked(buf, n, stream);
    if buf_ret.is_null() {
        // Read failed
        *ret_label = 0;
        return buf_ret;
    } else {
        *ret_label = buf_label;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return buf_ret;
    }

    // fgets is guaranteed to append a \0 if it succeeds
    let bytes_read = libc::strlen(buf);

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return buf_ret;
    };

    // stream is valid, otherwise fgets would have failed
    // offset is positive, checked before
    tainter.trace_read(
        libc::fileno(stream),
        buf.cast(),
        offset as usize,
        bytes_read,
    );

    buf_ret
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_getline(
    lineptr: *mut *mut c_char,
    n: *mut size_t,
    stream: *mut FILE,
    _lineptr_label: dfsan_label,
    _n_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> ssize_t {
    safe_debug!("Wrapper called: {}", "getline");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let bytes_read = libc::getline(lineptr, n, stream);
    if bytes_read <= 0 {
        // No read occurred
        return bytes_read;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return bytes_read;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return bytes_read;
    };

    // stream is valid, otherwise getline would have failed
    // offset and bytes_read are positive, checked before
    tainter.trace_read(
        libc::fileno(stream),
        *lineptr.cast(),
        offset as usize,
        bytes_read as usize,
    );

    bytes_read
}

#[no_mangle]
pub unsafe extern "C" fn __dfsw_getdelim(
    lineptr: *mut *mut c_char,
    n: *mut size_t,
    delim: c_int,
    stream: *mut FILE,
    _lineptr_label: dfsan_label,
    _n_label: dfsan_label,
    _delim_label: dfsan_label,
    _stream_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> ssize_t {
    safe_debug!("Wrapper called: {}", "getdelim");
    *ret_label = 0;

    let offset = libc::ftell(stream);

    let bytes_read = getdelim(lineptr, n, delim, stream);
    if bytes_read <= 0 {
        // No read occurred
        return bytes_read;
    }

    if offset < 0 {
        safe_warn!(
            "Could not retrieve file offset: {}",
            get_c_error().to_string_lossy()
        );

        return bytes_read;
    }

    let mut tainter = if let Some(tainter) = Tainter::global() {
        tainter
    } else {
        safe_warn!("Tainter not initialized");
        return bytes_read;
    };

    // stream is valid, otherwise getdelim would have failed
    // offset and bytes_read are positive, checked before
    tainter.trace_read(
        libc::fileno(stream),
        *lineptr.cast(),
        offset as usize,
        bytes_read as usize,
    );

    bytes_read
}

fn get_c_error() -> &'static CStr {
    unsafe {
        let errno = *libc::__errno_location();
        CStr::from_ptr(libc::strerror(errno))
    }
}

extern "C" {
    fn __real___dfsw_strchr(
        cs: *const c_char,
        c: c_int,
        cs_label: dfsan_label,
        c_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> *mut c_char;

    fn __real___dfsw_memcmp(
        cx: *const c_void,
        ct: *const c_void,
        n: size_t,
        cx_label: dfsan_label,
        ct_label: dfsan_label,
        n_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_int;

    fn __real___dfsw_strcmp(
        cs: *const c_char,
        ct: *const c_char,
        cs_label: dfsan_label,
        ct_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_int;

    fn __real___dfsw_strcasecmp(
        s1: *const c_char,
        s2: *const c_char,
        s1_label: dfsan_label,
        s2_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_int;

    fn __real___dfsw_strncmp(
        cs: *const c_char,
        ct: *const c_char,
        n: size_t,
        cs_label: dfsan_label,
        ct_label: dfsan_label,
        n_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_int;

    fn __real___dfsw_strncasecmp(
        s1: *const c_char,
        s2: *const c_char,
        n: size_t,
        s1_label: dfsan_label,
        s2_label: dfsan_label,
        n_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_int;

    fn __real___dfsw_strlen(
        cs: *const c_char,
        cs_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> size_t;

    fn __real___dfsw_memchr(
        cx: *const c_void,
        c: c_int,
        n: size_t,
        cx_label: dfsan_label,
        c_label: dfsan_label,
        n_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> *mut c_void;

    fn __real___dfsw_strrchr(
        cs: *const c_char,
        c: c_int,
        cs_label: dfsan_label,
        c_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> *mut c_char;

    fn __real___dfsw_strstr(
        cs: *const c_char,
        ct: *const c_char,
        cs_label: dfsan_label,
        ct_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> *mut c_char;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strchr(
    cs: *const c_char,
    c: c_int,
    cs_label: dfsan_label,
    c_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_char {
    safe_debug!("Wrapper called: {}", "strchr");

    let target_ptr = __real___dfsw_strchr(cs, c, cs_label, c_label, ret_label);

    let load_size = if target_ptr.is_null() {
        // The target char has not been found, so the whole string has been loaded into memory.
        let string_length = libc::strlen(cs);

        // The NULL terminator has been loaded as well, so check its label as well.
        string_length + 1
    } else {
        // Only the portion of the string up to the target has been loaded.
        let target_offset = target_ptr.offset_from(cs);
        assert!(!target_offset.is_negative());

        // The element pointed to is included, so add 1.
        (target_offset + 1) as usize
    };

    let load_label = dfsan_read_label(cs as *const libc::c_void, load_size);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    target_ptr
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_memcmp(
    cx: *const c_void,
    ct: *const c_void,
    n: size_t,
    cx_label: dfsan_label,
    ct_label: dfsan_label,
    n_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    // XXX: This wrapper is safe but not precise since it assumes `n` bytes are always read.
    safe_debug!("Wrapper called: {}", "memcmp");

    if dfsan_read_label(cx, n) != 0 || dfsan_read_label(ct, n) != 0 {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_memcmp(cx, ct, n, cx_label, ct_label, n_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strcmp(
    cs: *const c_char,
    ct: *const c_char,
    cs_label: dfsan_label,
    ct_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    // XXX: This wrapper is safe but not precise since it assumes that the
    // entire length of the shortest string is always loaded.
    safe_debug!("Wrapper called: {}", "strcmp");

    // When equal, the strings have the same length and they are loaded
    // entirely. When unequal, if they have different length, only the shortest
    // one may be read entirely.

    let load_size_1 = libc::strlen(cs) + 1;
    let load_size_2 = libc::strlen(ct) + 1;

    // The NULL terminator is loaded as well, so check it.
    let load_size = min(load_size_1, load_size_2);
    if dfsan_read_label(cs as *const libc::c_void, load_size) != 0
        || dfsan_read_label(ct as *const libc::c_void, load_size) != 0
    {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_strcmp(cs, ct, cs_label, ct_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strcasecmp(
    s1: *const c_char,
    s2: *const c_char,
    s1_label: dfsan_label,
    s2_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    // XXX: This wrapper is safe but not precise since it assumes that the
    // entire length of the shortest string is always loaded.
    safe_debug!("Wrapper called: {}", "strcasecmp");

    // When equal, the strings have the same length and they are loaded
    // entirely. When unequal, if they have different length, only the shortest
    // one may be read entirely.

    let load_size_1 = libc::strlen(s1) + 1;
    let load_size_2 = libc::strlen(s2) + 1;

    // The NULL terminator is loaded as well, so check it.
    let load_size = min(load_size_1, load_size_2);
    if dfsan_read_label(s1 as *const libc::c_void, load_size) != 0
        || dfsan_read_label(s2 as *const libc::c_void, load_size) != 0
    {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_strcasecmp(s1, s2, s1_label, s2_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strncmp(
    cs: *const c_char,
    ct: *const c_char,
    n: size_t,
    cs_label: dfsan_label,
    ct_label: dfsan_label,
    n_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    // XXX: This wrapper is safe but not precise since it assumes that the
    // entire length of the shortest string is always loaded.
    safe_debug!("Wrapper called: {}", "strncmp");

    // When equal, the strings have the same length and they are loaded
    // entirely. When unequal, if they have different length, only the shortest
    // one may be read entirely. If the strings are longer than n, then only n
    // bytes are loaded.

    // The NULL terminator is loaded as well, so check it.
    let possible_load_sizes = [libc::strlen(cs) + 1, libc::strlen(ct) + 1, n];

    let load_size = possible_load_sizes.iter().min().unwrap();
    if dfsan_read_label(cs as *const libc::c_void, *load_size) != 0
        || dfsan_read_label(ct as *const libc::c_void, *load_size) != 0
    {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_strncmp(cs, ct, n, cs_label, ct_label, n_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strncasecmp(
    s1: *const c_char,
    s2: *const c_char,
    n: size_t,
    s1_label: dfsan_label,
    s2_label: dfsan_label,
    n_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_int {
    // XXX: This wrapper is safe but not precise since it assumes that the
    // entire length of the shortest string is always loaded.
    safe_debug!("Wrapper called: {}", "strncasecmp");

    // When equal, the strings have the same length and they are loaded
    // entirely. When unequal, if they have different length, only the shortest
    // one may be read entirely. If the strings are longer than n, then only n
    // bytes are loaded.

    // The NULL terminator is loaded as well, so check it.
    let possible_load_sizes = [libc::strlen(s1) + 1, libc::strlen(s2) + 1, n];

    let load_size = possible_load_sizes.iter().min().unwrap();
    if dfsan_read_label(s1 as *const libc::c_void, *load_size) != 0
        || dfsan_read_label(s2 as *const libc::c_void, *load_size) != 0
    {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_strncasecmp(s1, s2, n, s1_label, s2_label, n_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strlen(
    cs: *const c_char,
    cs_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> size_t {
    safe_debug!("Wrapper called: {}", "strlen");

    let length = __real___dfsw_strlen(cs, cs_label, ret_label);

    // The NULL terminator is loaded as well, so check it.
    if dfsan_read_label(cs as *const libc::c_void, length + 1) != 0 {
        trigger_tracer();
        unreachable!();
    }

    length
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_memchr(
    cx: *const c_void,
    c: c_int,
    n: size_t,
    cx_label: dfsan_label,
    c_label: dfsan_label,
    n_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_void {
    safe_debug!("Wrapper called: {}", "memchr");

    let target_ptr = __real___dfsw_memchr(cx, c, n, cx_label, c_label, n_label, ret_label);

    let load_size = if target_ptr.is_null() {
        n
    } else {
        // Only the portion of the buffer up to the target has been loaded.
        let target_offset = target_ptr.offset_from(cx);
        assert!(!target_offset.is_negative());

        // The element pointed to is included, so add 1.
        (target_offset + 1) as usize
    };

    let load_label = dfsan_read_label(cx as *const libc::c_void, load_size);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    target_ptr
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strrchr(
    cs: *const c_char,
    c: c_int,
    cs_label: dfsan_label,
    c_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_char {
    safe_debug!("Wrapper called: {}", "strrchr");

    // The NULL terminator is loaded as well, so check it.
    let load_size = libc::strlen(cs) + 1;

    let load_label = dfsan_read_label(cs as *const libc::c_void, load_size);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    __real___dfsw_strrchr(cs, c, cs_label, c_label, ret_label)
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strstr(
    cs: *const c_char,
    ct: *const c_char,
    cs_label: dfsan_label,
    ct_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> *mut c_char {
    safe_debug!("Wrapper called: {}", "strstr");

    let target_ptr = __real___dfsw_strstr(cs, ct, cs_label, ct_label, ret_label);

    let load_size = if target_ptr.is_null() {
        // The target substring has not been found, so the whole string has been loaded into memory.
        let haystack_length = libc::strlen(cs);

        // The NULL terminator has been loaded as well, so check its label as well.
        haystack_length + 1
    } else {
        // Only the portion of the string up to the end of the substring has been loaded.
        let target_offset = target_ptr.offset_from(cs);
        assert!(!target_offset.is_negative());

        let needle_length = libc::strlen(ct);
        target_offset as usize + needle_length
    };

    let load_label = dfsan_read_label(cs as *const libc::c_void, load_size);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    target_ptr
}

extern "C" {
    fn __real___dfsw_strtol(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        nptr_label: dfsan_label,
        endptr_label: dfsan_label,
        base_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_long;

    fn __real___dfsw_strtod(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        nptr_label: dfsan_label,
        endptr_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_double;

    fn __real___dfsw_strtoll(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        nptr_label: dfsan_label,
        endptr_label: dfsan_label,
        base_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_longlong;

    fn __real___dfsw_strtoul(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        nptr_label: dfsan_label,
        endptr_label: dfsan_label,
        base_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_ulong;

    fn __real___dfsw_strtoull(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        nptr_label: dfsan_label,
        endptr_label: dfsan_label,
        base_label: dfsan_label,
        ret_label: *mut dfsan_label,
    ) -> c_ulonglong;

}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    nptr_label: dfsan_label,
    endptr_label: dfsan_label,
    base_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_long {
    let end_pointer_addr = if endptr.is_null() {
        &mut ptr::null_mut()
    } else {
        endptr
    };

    let result = __real___dfsw_strtol(
        nptr,
        end_pointer_addr,
        base,
        nptr_label,
        endptr_label,
        base_label,
        ret_label,
    );

    let load_size = (*end_pointer_addr).offset_from(nptr);
    assert!(!load_size.is_negative());

    let load_label = dfsan_read_label(nptr as *const libc::c_void, load_size as usize);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strtod(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    nptr_label: dfsan_label,
    endptr_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_double {
    let end_pointer_addr = if endptr.is_null() {
        &mut ptr::null_mut()
    } else {
        endptr
    };

    let result = __real___dfsw_strtod(nptr, end_pointer_addr, nptr_label, endptr_label, ret_label);

    let load_size = (*end_pointer_addr).offset_from(nptr);
    assert!(!load_size.is_negative());

    let load_label = dfsan_read_label(nptr as *const libc::c_void, load_size as usize);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strtoll(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    nptr_label: dfsan_label,
    endptr_label: dfsan_label,
    base_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_longlong {
    let end_pointer_addr = if endptr.is_null() {
        &mut ptr::null_mut()
    } else {
        endptr
    };

    let result = __real___dfsw_strtoll(
        nptr,
        end_pointer_addr,
        base,
        nptr_label,
        endptr_label,
        base_label,
        ret_label,
    );

    let load_size = (*end_pointer_addr).offset_from(nptr);
    assert!(!load_size.is_negative());

    let load_label = dfsan_read_label(nptr as *const libc::c_void, load_size as usize);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    nptr_label: dfsan_label,
    endptr_label: dfsan_label,
    base_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_ulong {
    let end_pointer_addr = if endptr.is_null() {
        &mut ptr::null_mut()
    } else {
        endptr
    };

    let result = __real___dfsw_strtoul(
        nptr,
        end_pointer_addr,
        base,
        nptr_label,
        endptr_label,
        base_label,
        ret_label,
    );

    let load_size = (*end_pointer_addr).offset_from(nptr);
    assert!(!load_size.is_negative());

    let load_label = dfsan_read_label(nptr as *const libc::c_void, load_size as usize);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    nptr_label: dfsan_label,
    endptr_label: dfsan_label,
    base_label: dfsan_label,
    ret_label: *mut dfsan_label,
) -> c_ulonglong {
    let end_pointer_addr = if endptr.is_null() {
        &mut ptr::null_mut()
    } else {
        endptr
    };

    let result = __real___dfsw_strtoull(
        nptr,
        end_pointer_addr,
        base,
        nptr_label,
        endptr_label,
        base_label,
        ret_label,
    );

    let load_size = (*end_pointer_addr).offset_from(nptr);
    assert!(!load_size.is_negative());

    let load_label = dfsan_read_label(nptr as *const libc::c_void, load_size as usize);
    if load_label != 0 {
        trigger_tracer();
        unreachable!();
    }

    result
}

// These two functions are not easily implementable, no functions with a va_list
// parameter in compiler-rt. It could be possible to implement svprintf in
// compiler-rt and then reuse that implementation in this project.

extern "C" {
    pub fn format_buffer(
        buffer: *mut c_char,
        size: usize,
        format: *const c_char,
        va_labels: *mut dfsan_label,
        ret_label: *mut dfsan_label,
        ap: VaList,
    ) -> c_int;
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_sprintf(
    buffer: *mut c_char,
    format: *const c_char,
    _str_label: dfsan_label,
    _format_label: dfsan_label,
    va_labels: *mut dfsan_label,
    ret_label: *mut dfsan_label,
    mut args: ...
) -> c_int {
    let result = heap_tracer::with_tracer_disabled(|| {
        format_buffer(
            buffer,
            usize::MAX,
            format,
            va_labels,
            ret_label,
            args.as_va_list(),
        )
    });

    if result <= 0 {
        return result;
    }

    // If the output buffer is tainted, then one of the arguments was tainted as
    // well. Trigger the snapshot accordingly.
    let output_label = dfsan_read_label(buffer.cast::<c_void>(), result as usize);
    if output_label != 0 {
        // Acting as if the snapshot was triggered before running sprintf. If
        // there was tainted data before, it will get overwritten by sprintf
        // right after the snapshot.
        dfsan_set_label(0, buffer.cast::<c_void>(), result as usize);
        trigger_tracer();
        unreachable!();
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn __wrap___dfsw_snprintf(
    buffer: *mut c_char,
    size: size_t,
    format: *const c_char,
    _str_label: dfsan_label,
    _size_label: dfsan_label,
    _format_label: dfsan_label,
    va_labels: *mut dfsan_label,
    ret_label: *mut dfsan_label,
    mut args: ...
) -> c_int {
    let result = heap_tracer::with_tracer_disabled(|| {
        format_buffer(
            buffer,
            size,
            format,
            va_labels,
            ret_label,
            args.as_va_list(),
        )
    });

    if result <= 0 {
        return result;
    }

    let written_bytes = min(result as usize, size);

    // If the output buffer is tainted, then one of the arguments was tainted as
    // well. Trigger the snapshot accordingly.
    let output_label = dfsan_read_label(buffer.cast::<c_void>(), written_bytes);
    if output_label != 0 {
        // Acting as if the snapshot was triggered before running sprintf. If
        // there was tainted data before, it will get overwritten by sprintf
        // right after the snapshot.
        dfsan_set_label(0, buffer.cast::<c_void>(), written_bytes);
        trigger_tracer();
        unreachable!();
    }

    result
}

// The following functions, despite loading values, copy them to a new location
// without leaving information in registers. As a consequence, these loads are
// reproducible by the snapshotting system.
// memcpy
// strdup
// strncpy
// strcpy
