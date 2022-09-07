use backtrace::Backtrace;
use libc::{c_int, size_t};
use log::log_enabled;
use once_cell::sync::Lazy;
use rangemap::RangeMap;
use std::{
    alloc::{GlobalAlloc, System},
    cell::RefCell,
    collections::HashMap,
    ffi::CStr,
    mem,
    os::raw::c_void,
    process, ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    dfsan,
    tracer::{DataPtr, Tracer},
};

pub type AllocID = usize;

thread_local! {
    static TRACER_ENABLED: RefCell<bool> = RefCell::new(true);
}

#[derive(Default)]
pub struct HeapTracer {
    allocations: HashMap<DataPtr, AllocationInfo>,
    alloc_counter: AllocID,
}

impl HeapTracer {
    pub fn trace_alloc(&mut self, ptr: DataPtr, size: usize) {
        if log_enabled!(log::Level::Trace) {
            log::trace!("Heap allocation: {:?} ({} bytes)", ptr, size);
            let backtrace = Backtrace::new();
            Self::log_backtrace(&backtrace);
        }

        self.allocations.insert(
            ptr,
            AllocationInfo {
                id: self.alloc_counter,
                size,
            },
        );
        self.alloc_counter += 1;
    }

    pub fn trace_dealloc(&mut self, ptr: DataPtr) {
        log::trace!("Heap deallocation: {:?}", ptr);

        let removed_allocation = self.allocations.remove(&ptr);

        if log_enabled!(log::Level::Debug) && removed_allocation.is_none() {
            // At least three pointers per run will follow this route: two
            // buffers belonging to a thread local variable in `log` and the
            // allocation containing the destructor for that variable
            log::debug!("Unknown pointer: {:?}", ptr);
        };
    }

    pub fn export_range_map(&self) -> RangeMap<DataPtr, AllocID> {
        // Later allocations will replace the most recent ones in the map,
        // creating a correct representation of the current heap.
        self.allocations
            .iter()
            .map(|(&ptr_beg, info)| {
                let ptr_end = ptr_beg.add(info.size);
                (ptr_beg..ptr_end, info.id)
            })
            .collect()
    }

    pub fn get_allocations_count(&self) -> usize {
        self.alloc_counter
    }

    fn log_backtrace(backtrace: &Backtrace) {
        let backtrace_str = format!("{:?}", backtrace);
        for line in backtrace_str.lines() {
            log::trace!("{}", line);
        }
    }
}

struct AllocationInfo {
    pub id: AllocID,
    pub size: usize,
}

pub fn with_tracer_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let mut prev_tracer_enabled = true;

    // An error will be returned when `TRACER_ENABLED` has already been
    // destroyed. In that case, the tracer is no longer active, so just execute
    // the code without complaining, the hooks will not trace allocations.
    let result = TRACER_ENABLED.try_with(|tracer_enabled| {
        let mut tracer_enabled = tracer_enabled.borrow_mut();
        prev_tracer_enabled = *tracer_enabled;
        *tracer_enabled = false;
    });

    let ret = f();

    if result.is_ok() {
        TRACER_ENABLED.with(|tracer_enabled| *tracer_enabled.borrow_mut() = prev_tracer_enabled);
    }

    ret
}

fn resolve_symbol(name: &CStr) -> Result<*mut c_void, &'static str> {
    let address = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
    if address.is_null() {
        let error_message = unsafe { libc::dlerror() };
        assert_ne!(error_message, ptr::null_mut());

        let error_message = unsafe { CStr::from_ptr(error_message) };
        return Err(error_message
            .to_str()
            .expect("dlerror returned non-UTF-8 string"));
    }

    Ok(address)
}

type MallocFunc = fn(size: size_t) -> *mut c_void;
type FreeFunc = fn(ptr: *mut c_void);
type CallocFunc = fn(nmemb: size_t, size: size_t) -> *mut c_void;
type ReallocFunc = fn(ptr: *mut c_void, size: size_t) -> *mut c_void;
type PosixMemalignFunc = fn(memptr: *mut *mut c_void, alignment: size_t, size: size_t) -> c_int;

struct RealAllocFuncs {
    pub malloc: MallocFunc,
    pub free: FreeFunc,
    pub calloc: CallocFunc,
    pub realloc: ReallocFunc,
    pub posix_memalign: PosixMemalignFunc,
}

impl RealAllocFuncs {
    pub fn try_new() -> Result<RealAllocFuncs, &'static str> {
        INITIALIZING_ALLOC_FUNCS.store(true, Ordering::Relaxed);

        let malloc_name = CStr::from_bytes_with_nul(b"malloc\0").unwrap();
        let malloc_addr = resolve_symbol(malloc_name)?;

        let free_name = CStr::from_bytes_with_nul(b"free\0").unwrap();
        let free_addr = resolve_symbol(free_name)?;

        let calloc_name = CStr::from_bytes_with_nul(b"calloc\0").unwrap();
        let calloc_addr = resolve_symbol(calloc_name)?;

        let realloc_name = CStr::from_bytes_with_nul(b"realloc\0").unwrap();
        let realloc_addr = resolve_symbol(realloc_name)?;

        let posix_memalign_name = CStr::from_bytes_with_nul(b"posix_memalign\0").unwrap();
        let posix_memalign_addr = resolve_symbol(posix_memalign_name)?;

        let new_struct = unsafe {
            RealAllocFuncs {
                malloc: mem::transmute::<*mut c_void, MallocFunc>(malloc_addr),
                free: mem::transmute::<*mut c_void, FreeFunc>(free_addr),
                calloc: mem::transmute::<*mut c_void, CallocFunc>(calloc_addr),
                realloc: mem::transmute::<*mut c_void, ReallocFunc>(realloc_addr),
                posix_memalign: mem::transmute::<*mut c_void, PosixMemalignFunc>(
                    posix_memalign_addr,
                ),
            }
        };

        INITIALIZING_ALLOC_FUNCS.store(false, Ordering::Relaxed);

        Ok(new_struct)
    }
}

// Initialization is assumed to be single threaded, so a single atomic is
// sufficient to filter out the allocations performed by dlsym.
static INITIALIZING_ALLOC_FUNCS: AtomicBool = AtomicBool::new(false);

static REAL_ALLOC_FUNCS: Lazy<RealAllocFuncs> = Lazy::new(|| {
    RealAllocFuncs::try_new().unwrap_or_else(|error| {
        // It is necessary to die here because the resolution happens
        // lazily, before the ctor for this library has run.
        eprintln!("Could not initialize allocator functions: {}", error);
        process::exit(crate::FAILURE_EXIT_CODE);
    })
});

// All allocations that are performed during DFSan initialization will be
// ignored because, until the global `Tracer` has been initialized, the tracing
// will not work.

#[no_mangle]
pub unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    if INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed) {
        // dlsym calls malloc, but handles a failed allocation correctly, so
        // make it fail.
        return ptr::null_mut();
    }

    let allocation = (REAL_ALLOC_FUNCS.malloc)(size);
    if allocation.is_null() {
        return allocation;
    }

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if tracer_enabled {
        if let Some(mut tracer) = Tracer::global() {
            tracer.trace_alloc(allocation.into(), size as usize);
        }
    }

    allocation
}

#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: size_t, size: size_t) -> *mut c_void {
    if INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed) {
        // dlsym calls calloc, but handles a failed allocation correctly, so
        // make it fail.
        return ptr::null_mut();
    }

    let allocation = (REAL_ALLOC_FUNCS.calloc)(nmemb, size);
    if allocation.is_null() {
        return allocation;
    }

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if tracer_enabled {
        if let Some(mut tracer) = Tracer::global() {
            tracer.trace_alloc(allocation.into(), nmemb * size as usize);
        }
    }

    allocation
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    assert!(
        !INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed),
        "free called during alloc functions resolution"
    );

    (REAL_ALLOC_FUNCS.free)(ptr);

    if !ptr.is_null() {
        remove_taints_from_freelist_ptrs(ptr);
    }

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if tracer_enabled {
        if let Some(mut tracer) = Tracer::global() {
            tracer.trace_dealloc(ptr.into());
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    assert!(
        !INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed),
        "realloc called during alloc functions resolution"
    );

    let allocation = (REAL_ALLOC_FUNCS.realloc)(ptr, size);
    if allocation.is_null() {
        return allocation;
    }

    if !ptr.is_null() && (allocation != ptr || size == 0) {
        remove_taints_from_freelist_ptrs(ptr);
    }

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if tracer_enabled {
        if let Some(mut tracer) = Tracer::global() {
            tracer.trace_dealloc(ptr.into());
            tracer.trace_alloc(allocation.into(), size as usize);
        }
    }

    allocation
}

#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: size_t,
    size: size_t,
) -> c_int {
    assert!(
        !INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed),
        "posix_memalign called during alloc functions resolution"
    );

    let result = (REAL_ALLOC_FUNCS.posix_memalign)(memptr, alignment, size);
    if result != 0 {
        return result;
    }

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if tracer_enabled {
        if let Some(mut tracer) = Tracer::global() {
            let allocation = *memptr;
            tracer.trace_alloc(allocation.into(), size as usize);
        }
    }

    result
}

// When using glibc, the first 4 pointers of a freed chunk are used by the
// freelist. Since glibc is not instrumented, the shadow is not correctly reset
// to zero when these pointers are written.
const FREELIST_PTRS_SIZE: usize = mem::size_of::<*mut c_void>() * 4;

unsafe fn remove_taints_from_freelist_ptrs(ptr: *mut c_void) {
    dfsan::dfsan_set_label(0, ptr, FREELIST_PTRS_SIZE);
}

struct MaskedAllocator(System);

unsafe impl GlobalAlloc for MaskedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        with_tracer_disabled(|| self.0.alloc(layout))
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        with_tracer_disabled(|| self.0.alloc_zeroed(layout))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        with_tracer_disabled(|| self.0.dealloc(ptr, layout))
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        with_tracer_disabled(|| self.0.realloc(ptr, layout, new_size))
    }
}

#[global_allocator]
static A: MaskedAllocator = MaskedAllocator(System);
