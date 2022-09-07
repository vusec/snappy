use crate::{
    heap_tracer::{self, AllocID, HeapTracer},
    stack_map_cache::{self, StackMapCache},
    symbols_cache,
    symbols_cache::ReversedSymbolsCache,
};
use bumpalo::Bump;
use fallible_iterator::FallibleIterator;
use findshlibs::{IterationControl, SharedLibrary, TargetSharedLibrary};
use log::log_enabled;
use mmap_allocator::MMapAllocator;
use serde::Deserialize;
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use stackmap::LocationKind;
use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs::File,
    io::BufReader,
    ops::Range,
    path::{Path, PathBuf},
    pin::Pin,
    time::Instant,
};
use unwind::{get_context, Cursor, RegNum};

pub struct Resolver {
    taints_path: PathBuf,

    stack_maps_cache: StackMapCache,
    symbols_cache: ReversedSymbolsCache<&'static Bump<MMapAllocator>>,
    heap_tracer: HeapTracer,

    // It has to be dropped last, so it needs to be at the end of the struct.
    bump: Pin<Box<Bump<MMapAllocator>>>,
}

// `Bump` is required to be `Sync` because a reference to it appears in other
// members of `Resolver`, which is required to be `Send`. The `Send` requirement
// derives from putting `Resolver` into a `Mutex`, which contains the instance
// of `Bump` being used as well, making it safe to use across threads. For this
// reason, the whole structure can be marked as `Send` safely.
unsafe impl<'a> Send for Resolver {}

impl Resolver {
    pub fn trace_alloc(&mut self, ptr: DataPtr, size: usize) {
        heap_tracer::with_tracer_disabled(|| {
            self.heap_tracer.trace_alloc(ptr, size);
        })
    }

    pub fn trace_dealloc(&mut self, ptr: DataPtr) {
        heap_tracer::with_tracer_disabled(|| {
            self.heap_tracer.trace_dealloc(ptr);
        })
    }

    pub fn disable_heap_tracing(&mut self) {
        self.heap_tracer.disable();
    }

    pub fn resolve_taints(&mut self) -> Result<Vec<(*mut u8, usize)>, Error> {
        let heap_map = self.heap_tracer.export_range_map();
        let allocation_map: BTreeMap<AllocID, Range<DataPtr>> = heap_map
            .iter()
            .map(|(range, id)| (*id, range.clone()))
            .collect();
        log::debug!(
            "Heap allocations observed: {}",
            self.heap_tracer.get_allocations_count()
        );

        let taints_file = File::open(&self.taints_path).context(TaintsFileOpenFail)?;
        let taints_reader = BufReader::new(taints_file);
        let tainted_bytes: Vec<(AddressKind, usize)> =
            serde_json::from_reader(taints_reader).context(TaintsDeserializeFail)?;

        let mut resolved_taints = Vec::with_capacity(tainted_bytes.len());
        for (tainted_info, tainted_offset) in tainted_bytes {
            log::trace!("Offset {} taints: {:?}", tainted_offset, tainted_info);

            let resolved_address = match tainted_info {
                AddressKind::Stack {
                    record_id,
                    location_idx,
                    location_offt,
                    stack_map_num_functions_hint,
                    stack_map_file_hint,
                } => self.resolve_stack_address(
                    record_id,
                    location_idx,
                    location_offt,
                    stack_map_num_functions_hint,
                    stack_map_file_hint,
                )?,
                AddressKind::Heap { id, size, offset } => {
                    self.resolve_heap_address(id, size, offset, &allocation_map)?
                }
                AddressKind::Static {
                    symbol,
                    symbol_idx,
                    offset,
                    binary_path,
                } => self.resolve_static_address(&symbol, symbol_idx, offset, binary_path)?,
            };

            log::trace!("Resolved to address: {:?}", resolved_address);

            resolved_taints.push((resolved_address, tainted_offset));
        }

        Ok(resolved_taints)
    }

    fn resolve_stack_address(
        &mut self,
        record_id: u64,
        location_idx: usize,
        location_offt: usize,
        stack_map_num_functions_hint: usize,
        stack_map_file_hint: PathBuf,
    ) -> Result<*mut u8, Error> {
        // Using the file hint allows me to avoid having to check all the files
        // currently loaded for stack maps
        let llvm_stack_maps = self
            .stack_maps_cache
            .get_stack_map(&stack_map_file_hint)
            .context(StackMapCacheError)?;

        let mut target_function = None;
        let mut target_record = None;
        let mut stack_maps = llvm_stack_maps.stack_maps();
        'stack_maps_loop: while let Some(stack_map) =
            stack_maps.next().context(StackMapDecodeError)?
        {
            // Using the hint on the number of functions in the stack map allows
            // me to skip a stackmap immediately instead of going through its
            // records
            if stack_map.num_functions() == stack_map_num_functions_hint {
                let mut functions = stack_map.functions();
                while let Some(function) = functions.next().context(StackMapDecodeError)? {
                    let mut records = function.records();
                    while let Some(record) = records.next().context(StackMapDecodeError)? {
                        let current_record_id = record.patch_point_id();
                        if current_record_id == record_id {
                            target_function = Some(function);
                            target_record = Some(record);
                            break 'stack_maps_loop;
                        }
                    }
                }
            }
        }

        let target_function = target_function.context(TargetRecordNotFound)?;
        let target_record = target_record.context(TargetRecordNotFound)?;

        let target_location = target_record
            .locations()
            .nth(location_idx)
            .context(StackMapDecodeError)?
            .context(TargetLocationNotFound)?;

        let (location_register, location_register_offt) = match target_location.kind() {
            LocationKind::Direct { register, offset } => {
                let reg_num = match *register {
                    6 => RegNum::RBP,
                    _ => unimplemented!("Unsupported DWARF register number"),
                };

                (reg_num, offset)
            }
            _ => return MismatchedLocationKind.fail(),
        };

        let mut target_register_value = None;
        {
            get_context!(unwind_context);
            let mut cursor = Cursor::local(unwind_context).context(UnwindFailed)?;
            loop {
                let current_func_addr = cursor.procedure_info().context(UnwindFailed)?.start_ip();
                if current_func_addr == target_function.address() {
                    target_register_value =
                        Some(cursor.register(location_register).context(UnwindFailed)?);
                    break;
                }

                if !cursor.step().context(UnwindFailed)? {
                    break;
                }
            }
        }

        let target_register_value = target_register_value.context(TargetFrameNotFound)? as *mut u8;
        let target_location_base = unsafe { target_register_value.offset(*location_register_offt) };
        let target_address = unsafe { target_location_base.add(location_offt) };
        log::trace!(
            "Resolved to register: {:?}, location: {:?}, target: {:?}",
            target_register_value,
            target_location_base,
            target_address
        );

        Ok(target_address)
    }

    fn resolve_heap_address(
        &self,
        alloc_id: usize,
        reported_size: usize,
        offset: usize,
        heap_map: &BTreeMap<AllocID, Range<DataPtr>>,
    ) -> Result<*mut u8, Error> {
        let alloc_range = heap_map
            .get(&alloc_id)
            .context(HeapAllocNotFound { alloc_id })?;

        let actual_size = alloc_range.end.offset_from(alloc_range.start) as usize;
        ensure!(
            reported_size == actual_size,
            HeapAllocSizeMismatch {
                alloc_id,
                reported_size,
                actual_size,
            }
        );

        Ok(alloc_range.start.offset(offset as isize).into_raw() as *mut _)
    }

    fn resolve_static_address(
        &mut self,
        symbol: &str,
        symbol_idx: usize,
        offset: usize,
        binary_path: impl AsRef<Path>,
    ) -> Result<*mut u8, Error> {
        let reversed_symbols_map = self
            .symbols_cache
            .get_symbols_for_binary(binary_path)
            .context(SymbolsCacheError)?;
        let symbol_range = reversed_symbols_map
            .get_range_for_symbol(symbol, symbol_idx)
            .context(SymbolNotFound)?;
        log::trace!("Target symbol address: {:?}", symbol_range.start);
        Ok(symbol_range.start.offset(offset as isize).into_raw() as *mut _)
    }

    pub fn log_allocator_info(&mut self) {
        log::debug!(
            "Bump allocator used {} chunks.",
            self.bump.iter_allocated_chunks().count()
        );

        if log_enabled!(log::Level::Trace) {
            for chunk in self.bump.iter_allocated_chunks() {
                log::trace!("chunk: {:?}", chunk.as_ptr_range());
            }
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type")]
enum AddressKind {
    Stack {
        record_id: u64,
        location_idx: usize,
        location_offt: usize,
        stack_map_num_functions_hint: usize,
        stack_map_file_hint: PathBuf,
    },
    Static {
        symbol: String,
        symbol_idx: usize,
        offset: usize,
        binary_path: PathBuf,
    },
    Heap {
        id: AllocID,
        size: usize,
        offset: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataPtr(*const u8);

impl DataPtr {
    pub fn offset_from(self, other: DataPtr) -> isize {
        unsafe { self.0.offset_from(other.0) }
    }

    pub fn offset(self, count: isize) -> DataPtr {
        unsafe { DataPtr::from(self.0.offset(count)) }
    }

    pub fn add(self, count: usize) -> DataPtr {
        unsafe { DataPtr::from(self.0.add(count)) }
    }

    pub fn sub(self, count: usize) -> DataPtr {
        unsafe { DataPtr::from(self.0.sub(count)) }
    }

    pub fn into_raw(self) -> *const u8 {
        self.0
    }
}

unsafe impl Send for DataPtr {}

impl<T> From<*const T> for DataPtr {
    fn from(ptr: *const T) -> Self {
        Self(ptr as *const u8)
    }
}

impl<T> From<*mut T> for DataPtr {
    fn from(ptr: *mut T) -> Self {
        Self(ptr as *const u8)
    }
}

impl From<DataPtr> for *const u8 {
    fn from(ptr: DataPtr) -> Self {
        ptr.0
    }
}

impl Debug for DataPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub struct ResolverBuilder {
    taints_path: Option<PathBuf>,

    stack_maps_cache: StackMapCache,
    symbols_cache: ReversedSymbolsCache<&'static Bump<MMapAllocator>>,

    // It has to be dropped last, so it needs to be at the end of the struct.
    bump: Pin<Box<Bump<MMapAllocator>>>,
}

impl ResolverBuilder {
    pub fn new() -> Self {
        // `bump` needs to be pinned so that the reference passed to the caches
        // will remain valid for the whole lifetime of the `Resolver`.
        let bump = Box::pin(Bump::with_capacity_in(64 * 4096, MMapAllocator));

        // The allocations in the caches are guaranteed to last at least as long
        // as `bump` because of the `Drop` order in `Resolver`.
        let bump_ptr: *const _ = bump.as_ref().get_ref();
        let bump_ref = unsafe { &*bump_ptr };

        Self {
            taints_path: None,

            stack_maps_cache: StackMapCache::default(),
            symbols_cache: ReversedSymbolsCache::new_in(bump_ref),

            bump,
        }
    }

    pub fn taints_path(&mut self, taints_path: PathBuf) -> &mut Self {
        self.taints_path = Some(taints_path);
        self
    }

    pub fn prefill_caches(&mut self) -> Result<(), Error> {
        let begin = Instant::now();

        let mut result = Ok(());
        TargetSharedLibrary::each(|shlib| {
            let object_path: PathBuf = shlib.name().into();

            // Skip VDSO because it is not present on disk, skip empty string found in some binaries.
            if object_path == Path::new("linux-vdso.so.1") || object_path == Path::new("") {
                return IterationControl::Continue;
            }

            if let Err(error) = self.stack_maps_cache.get_stack_map(&object_path) {
                if !matches!(error, stack_map_cache::Error::StackMapsSectionNotFound) {
                    result = Err(error).context(StackMapCacheError);
                    return IterationControl::Break;
                }
            }

            if let Err(error) = self.symbols_cache.get_symbols_for_binary(&object_path) {
                result = Err(error).context(SymbolsCacheError);
                return IterationControl::Break;
            }

            IterationControl::Continue
        });

        log::debug!("Precaching took: {:?}", begin.elapsed());

        result
    }

    pub fn build(self) -> Resolver {
        Resolver {
            taints_path: self.taints_path.expect("Missing taints_path"),

            stack_maps_cache: self.stack_maps_cache,
            symbols_cache: self.symbols_cache,
            heap_tracer: Default::default(),

            bump: self.bump,
        }
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Could not open taints file: {}", source))]
    TaintsFileOpenFail {
        source: std::io::Error,
    },
    #[snafu(display("Could not deserialize taints file: {}", source))]
    TaintsDeserializeFail {
        source: serde_json::Error,
    },
    StackMapCacheError {
        source: crate::stack_map_cache::Error,
    },
    StackMapDecodeError {
        source: stackmap::Error,
    },
    TargetRecordNotFound,
    TargetLocationNotFound,
    TargetFrameNotFound,
    MismatchedLocationKind,
    #[snafu(display("Could not perform stack unwinding: {}", source))]
    UnwindFailed {
        source: unwind::Error,
    },
    #[snafu(display("Heap allocation not found: {}", alloc_id))]
    HeapAllocNotFound {
        alloc_id: usize,
    },
    #[snafu(display(
        "Heap allocation {} has size {} but should have size {}",
        alloc_id,
        reported_size,
        actual_size
    ))]
    HeapAllocSizeMismatch {
        alloc_id: usize,
        reported_size: usize,
        actual_size: usize,
    },
    SymbolsCacheError {
        source: symbols_cache::Error,
    },
    SymbolNotFound,
}
