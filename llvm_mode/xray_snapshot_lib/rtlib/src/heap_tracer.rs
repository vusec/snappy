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

use crate::{controller::Controller, resolver::DataPtr};

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

    pub fn disable(&mut self) {
        STOP_TRACING.store(true, Ordering::Release);
    }
}

struct AllocationInfo {
    pub id: AllocID,
    pub size: usize,
}

static STOP_TRACING: AtomicBool = AtomicBool::new(false);

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
        TRACER_ENABLED.with(|tracer_enabled| {
            let mut tracer_enabled = tracer_enabled.borrow_mut();

            // This check has to be performed here because `STOP_TRACING` can
            // only be set from within the `f` callback.
            if STOP_TRACING.load(Ordering::Acquire) {
                *tracer_enabled = false;
            } else {
                *tracer_enabled = prev_tracer_enabled
            }
        });
    }

    ret
}

fn is_tracing_stopped() -> bool {
    // Check if the tracing is stopped and set the thread local variable that
    // controls tracing accordingly so following allocations will not check the
    // atomic.
    if STOP_TRACING.load(Ordering::Acquire) {
        TRACER_ENABLED.with(|tracer_enabled| *tracer_enabled.borrow_mut() = false);
        true
    } else {
        false
    }
}

fn resolve_symbol(name: &CStr) -> Option<*mut c_void> {
    let address = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
    if !address.is_null() {
        Some(address)
    } else {
        None
    }
}

type MallocFunc = fn(size: size_t) -> *mut c_void;
type FreeFunc = fn(ptr: *mut c_void);
type CallocFunc = fn(nmemb: size_t, size: size_t) -> *mut c_void;
type ReallocFunc = fn(ptr: *mut c_void, size: size_t) -> *mut c_void;
type PosixMemalignFunc = fn(memptr: *mut *mut c_void, alignment: size_t, size: size_t) -> c_int;

#[derive(Default)]
struct AllocatorAPIBuilder<'a> {
    malloc_name: Option<&'a CStr>,
    free_name: Option<&'a CStr>,
    calloc_name: Option<&'a CStr>,
    realloc_name: Option<&'a CStr>,
    posix_memalign_name: Option<&'a CStr>,
}

impl<'a> AllocatorAPIBuilder<'a> {
    pub fn malloc_name(&mut self, malloc_name: &'a [u8]) -> &mut Self {
        self.malloc_name = Some(CStr::from_bytes_with_nul(malloc_name).unwrap());
        self
    }

    pub fn free_name(&mut self, free_name: &'a [u8]) -> &mut Self {
        self.free_name = Some(CStr::from_bytes_with_nul(free_name).unwrap());
        self
    }

    pub fn calloc_name(&mut self, calloc_name: &'a [u8]) -> &mut Self {
        self.calloc_name = Some(CStr::from_bytes_with_nul(calloc_name).unwrap());
        self
    }

    pub fn realloc_name(&mut self, realloc_name: &'a [u8]) -> &mut Self {
        self.realloc_name = Some(CStr::from_bytes_with_nul(realloc_name).unwrap());
        self
    }

    pub fn posix_memalign_name(&mut self, posix_memalign_name: &'a [u8]) -> &mut Self {
        self.posix_memalign_name = Some(CStr::from_bytes_with_nul(posix_memalign_name).unwrap());
        self
    }

    pub fn build(&mut self) -> Option<AllocatorAPI> {
        INITIALIZING_ALLOC_FUNCS.store(true, Ordering::Relaxed);

        // This lambda is used as a try/finally.
        let new_struct_result = || -> Option<AllocatorAPI> {
            let malloc_addr = resolve_symbol(self.malloc_name.expect("missing malloc name"))?;
            let free_addr = resolve_symbol(self.free_name.expect("missing free name"))?;
            let calloc_addr = resolve_symbol(self.calloc_name.expect("missing calloc name"))?;
            let realloc_addr = resolve_symbol(self.realloc_name.expect("missing realloc name"))?;
            let posix_memalign_addr = resolve_symbol(
                self.posix_memalign_name
                    .expect("missing posix_memalign name"),
            )?;

            let new_struct = unsafe {
                AllocatorAPI {
                    malloc: mem::transmute::<*mut c_void, MallocFunc>(malloc_addr),
                    free: mem::transmute::<*mut c_void, FreeFunc>(free_addr),
                    calloc: mem::transmute::<*mut c_void, CallocFunc>(calloc_addr),
                    realloc: mem::transmute::<*mut c_void, ReallocFunc>(realloc_addr),
                    posix_memalign: mem::transmute::<*mut c_void, PosixMemalignFunc>(
                        posix_memalign_addr,
                    ),
                }
            };

            Some(new_struct)
        }();

        INITIALIZING_ALLOC_FUNCS.store(false, Ordering::Relaxed);

        new_struct_result
    }
}

struct AllocatorAPI {
    pub malloc: MallocFunc,
    pub free: FreeFunc,
    pub calloc: CallocFunc,
    pub realloc: ReallocFunc,
    pub posix_memalign: PosixMemalignFunc,
}

impl AllocatorAPI {
    fn malloc(&self, size: size_t) -> *mut c_void {
        (self.malloc)(size)
    }

    fn free(&self, ptr: *mut c_void) {
        (self.free)(ptr)
    }

    fn calloc(&self, nmemb: size_t, size: size_t) -> *mut c_void {
        (self.calloc)(nmemb, size)
    }

    fn realloc(&self, ptr: *mut c_void, size: size_t) -> *mut c_void {
        (self.realloc)(ptr, size)
    }

    fn posix_memalign(&self, memptr: *mut *mut c_void, alignment: size_t, size: size_t) -> c_int {
        (self.posix_memalign)(memptr, alignment, size)
    }
}

// Initialization is assumed to be single threaded, so a single atomic is
// sufficient to filter out the allocations performed by dlsym.
static INITIALIZING_ALLOC_FUNCS: AtomicBool = AtomicBool::new(false);

static REAL_ALLOCATOR: Lazy<AllocatorAPI> = Lazy::new(|| {
    AllocatorAPIBuilder::default()
        .malloc_name(b"malloc\0")
        .free_name(b"free\0")
        .calloc_name(b"calloc\0")
        .realloc_name(b"realloc\0")
        .posix_memalign_name(b"posix_memalign\0")
        .build()
        .unwrap_or_else(|| {
            // It is necessary to die here because the resolution happens
            // lazily, before the ctor for this library has run.
            eprintln!("Could not initialize allocator functions");
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

    let allocation = REAL_ALLOCATOR.malloc(size);

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if !tracer_enabled || is_tracing_stopped() {
        return allocation;
    }

    if let Some(mut tracer) = Controller::global() {
        if !allocation.is_null() {
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

    let allocation = REAL_ALLOCATOR.calloc(nmemb, size);

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if !tracer_enabled || is_tracing_stopped() {
        return allocation;
    }

    if let Some(mut tracer) = Controller::global() {
        if !allocation.is_null() {
            tracer.trace_alloc(allocation.into(), nmemb * size as usize);
        }
    }

    allocation
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed) {
        panic!("free called during alloc functions resolution");
    }

    REAL_ALLOCATOR.free(ptr);

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if !tracer_enabled || is_tracing_stopped() {
        return;
    }

    if let Some(mut tracer) = Controller::global() {
        tracer.trace_dealloc(ptr.into());
    }
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    if INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed) {
        panic!("realloc called during alloc functions resolution");
    }

    let allocation = REAL_ALLOCATOR.realloc(ptr, size);

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if !tracer_enabled || is_tracing_stopped() {
        return allocation;
    }

    if let Some(mut tracer) = Controller::global() {
        if !allocation.is_null() {
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
    if INITIALIZING_ALLOC_FUNCS.load(Ordering::Relaxed) {
        panic!("posix_memalign called during alloc functions resolution");
    }

    let result = REAL_ALLOCATOR.posix_memalign(memptr, alignment, size);

    let tracer_enabled = TRACER_ENABLED
        .try_with(|tracer_enabled| *tracer_enabled.borrow())
        .unwrap_or(false);
    if !tracer_enabled || is_tracing_stopped() {
        return result;
    }

    if let Some(mut tracer) = Controller::global() {
        if result == 0 {
            let allocation = *memptr;
            tracer.trace_alloc(allocation.into(), size as usize);
        }
    }

    result
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
