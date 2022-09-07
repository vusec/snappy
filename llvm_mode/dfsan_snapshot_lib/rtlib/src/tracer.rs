use super::FunctionID;
use crate::{
    dfsan::dfsan_label,
    heap_tracer::{self, AllocID, HeapTracer},
    stack_map_cache,
    stack_map_cache::StackMapCache,
    symbols_cache,
    symbols_cache::SymbolsCache,
    tainter::Tainter,
    xray,
    xray::{XRayEntryType, XRayPatchingStatus},
};

use backtrace::Backtrace;
use fallible_iterator::FallibleIterator;
use libc::c_void;
use log::log_enabled;
use once_cell::sync::OnceCell;
use procfs::process::{MMapPath, MemoryMap, MemoryPageFlags, PageInfo, Process, SwapPageFlags};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use stackmap::LocationKind;
use unwind::{get_context, Context, Cursor, RegNum};

use std::{
    collections::BTreeMap,
    convert::TryInto,
    fmt::Debug,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    mem,
    mem::size_of,
    ops::Range,
    path::{Path, PathBuf},
    pin::Pin,
    slice,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

static TRACER: OnceCell<Mutex<Tracer>> = OnceCell::new();

#[derive(Default)]
pub struct Tracer {
    output_path_opt: Option<PathBuf>,
    stack_maps_cache: StackMapCache,
    symbols_cache: SymbolsCache,
    heap_tracer: HeapTracer,

    snapshot_target: Option<SnapshotTarget>,
}

impl Tracer {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        heap_tracer::with_tracer_disabled(|| {
            let lock = TRACER.get()?;
            Some(lock.lock().unwrap())
        })
    }

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

    pub unsafe fn patch_target_functions(&self) -> Result<(), TracerError> {
        log::debug!(
            "Patching target functions: {:?}",
            self.snapshot_target.as_ref().unwrap().target_ids()
        );
        for target_id in self.snapshot_target.as_ref().unwrap().target_ids() {
            let patch_status = xray::__xray_patch_function(*target_id);
            if patch_status != XRayPatchingStatus::SUCCESS {
                return PatchFailed {
                    function_id: *target_id,
                    status: patch_status,
                }
                .fail();
            }
        }

        Ok(())
    }

    pub unsafe fn unpatch_target_functions(&self) -> Result<(), TracerError> {
        if let Some(snapshot_target) = self.snapshot_target.as_ref() {
            log::debug!("Unpatching target functions");

            for target_id in snapshot_target.target_ids() {
                let patch_status = xray::__xray_unpatch_function(*target_id);
                if patch_status != XRayPatchingStatus::SUCCESS {
                    return PatchFailed {
                        function_id: *target_id,
                        status: patch_status,
                    }
                    .fail();
                }
            }
        }

        Ok(())
    }

    pub fn snapshot_target(&self) -> &SnapshotTarget {
        self.snapshot_target.as_ref().unwrap()
    }

    fn log_backtrace(&self, backtrace: &Backtrace) {
        let backtrace_str = format!("{:?}", backtrace);
        for line in backtrace_str.lines() {
            log::trace!("{}", line);
        }
    }

    fn record_tainted_bytes(
        &self,
        memory_maps: &[MemoryMap],
    ) -> Result<BTreeMap<DataPtr, usize>, TracerError> {
        let mut writable_maps = Vec::new();
        for map in memory_maps {
            if map.perms[1..2] == *"w" {
                writable_maps.push(map);
            }
        }
        log::debug!("Writable maps: {}", writable_maps.len());

        let page_size = procfs::page_size().context(PageSizeError)? as usize;
        let backed_shadow_pages =
            Self::find_backed_shadow_pages_in_writable_maps(&writable_maps, page_size)?;
        let tainted_bytes_map = Self::parse_backed_shadow_pages(&backed_shadow_pages, page_size);

        Ok(tainted_bytes_map)
    }

    fn find_backed_shadow_pages_in_writable_maps(
        writable_maps: &[&MemoryMap],
        page_size: usize,
    ) -> Result<Vec<(u64, u64)>, TracerError> {
        let process = Process::myself().context(ProcfsError)?;
        let mut pagemap = process.pagemap().context(ProcfsError)?;

        let mut interesting_shadow_pages = Vec::new();
        let parse_pagemap_begin = Instant::now();
        for map in writable_maps {
            let (start_address, end_address) = map.address;

            // Filter out the address of the shadow map
            if start_address == 0x000000010000 && end_address == 0x200200000000 {
                continue;
            }

            const ORIGINAL_MASK: u64 = 0b111 << 44;
            const SHADOW_MASK: u64 = !ORIGINAL_MASK;
            let start_shadow_address = (start_address & SHADOW_MASK) << 1;
            let end_shadow_address = (end_address & SHADOW_MASK) << 1;

            const SHADOW_MEMORY_TOP: u64 = 0x200000000000; // From compiler-rt/lib/dfsan/dfsan.cpp
            assert!(start_shadow_address < SHADOW_MEMORY_TOP);
            assert!(end_shadow_address <= SHADOW_MEMORY_TOP);

            let start_idx = start_shadow_address as usize / page_size;
            let end_idx = end_shadow_address as usize / page_size;

            let start_pagemap_read = Instant::now();
            let page_infos = pagemap
                .get_range_info(start_idx..end_idx)
                .context(ProcfsError)?;
            let end_pagemap_read = Instant::now();
            log::trace!(
                "Pagemap read took {:?} for map({:#x},{:#x})",
                end_pagemap_read.duration_since(start_pagemap_read),
                start_address,
                end_address,
            );
            log::trace!(
                "\tshadow({:#x}, {:#x}), {} entries",
                start_shadow_address,
                end_shadow_address,
                page_infos.len(),
            );

            for (idx, page_info) in page_infos.iter().enumerate() {
                let is_frame_present = match page_info {
                    PageInfo::MemoryPage(flags) => flags.contains(MemoryPageFlags::PRESENT),
                    PageInfo::SwapPage(flags) => flags.contains(SwapPageFlags::PRESENT),
                };
                if is_frame_present {
                    let shadow_page_base = start_shadow_address + idx as u64 * page_size as u64;
                    let original_base_address =
                        (shadow_page_base >> 1) | (start_address & ORIGINAL_MASK);
                    interesting_shadow_pages.push((shadow_page_base, original_base_address));
                }
            }
        }
        let parse_pagemap_end = Instant::now();
        log::debug!(
            "Backed corresponding shadow pages: {}",
            interesting_shadow_pages.len()
        );
        log::trace!(
            "Parsing pagemap took: {:?}",
            parse_pagemap_end.duration_since(parse_pagemap_begin)
        );

        Ok(interesting_shadow_pages)
    }

    fn parse_backed_shadow_pages(
        backed_shadow_pages: &[(u64, u64)],
        page_size: usize,
    ) -> BTreeMap<DataPtr, usize> {
        let tainter = Tainter::global().expect("Tainter not initialized");
        let translation_map = tainter.get_translation_map();

        let mut tainted_bytes_map: BTreeMap<DataPtr, usize> = BTreeMap::new();
        let parse_pages_begin = Instant::now();
        for &(shadow_page_start, original_base_address) in backed_shadow_pages {
            log::trace!(
                "Parsing page {:#x}, for original base {:#x}",
                shadow_page_start,
                original_base_address
            );

            Self::parse_backed_shadow_page(
                shadow_page_start as *const dfsan_label,
                original_base_address as usize,
                page_size,
                translation_map,
                &mut tainted_bytes_map,
            );
        }
        let parse_pages_end = Instant::now();

        log::debug!("Tainted bytes: {}", tainted_bytes_map.len());
        log::trace!(
            "Parsing pages took: {:?}",
            parse_pages_end.duration_since(parse_pages_begin)
        );

        tainted_bytes_map
    }

    fn parse_backed_shadow_page(
        shadow_page_ptr: *const dfsan_label,
        original_base_address: usize,
        page_size: usize,
        translation_map: &BTreeMap<dfsan_label, usize>,
        tainted_bytes_map: &mut BTreeMap<DataPtr, usize>,
    ) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                unsafe {
                    Self::parse_backed_shadow_page_avx2(
                        shadow_page_ptr,
                        original_base_address,
                        page_size,
                        translation_map,
                        tainted_bytes_map,
                    )
                };
                return;
            }
        }

        // DFSan guaratees that, on x86_64, all memory from 0x000000000000 to 0x200000000000 is mapped
        let shadow_page = unsafe {
            slice::from_raw_parts(shadow_page_ptr.cast::<u64>(), page_size / size_of::<u64>())
        };

        for (word_idx, &current_word) in shadow_page.iter().enumerate() {
            if current_word > 0 {
                Self::parse_backed_shadow_word(
                    current_word,
                    word_idx,
                    original_base_address,
                    translation_map,
                    tainted_bytes_map,
                );
            }
        }
    }

    unsafe fn parse_backed_shadow_page_avx2(
        shadow_page_ptr: *const dfsan_label,
        original_base_address: usize,
        page_size: usize,
        translation_map: &BTreeMap<dfsan_label, usize>,
        tainted_bytes_map: &mut BTreeMap<DataPtr, usize>,
    ) {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{
            __m256i, _mm256_cmpeq_epi8, _mm256_extract_epi64, _mm256_movemask_epi8,
            _mm256_setzero_si256,
        };
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{
            __m256i, _mm256_cmpeq_epi16, _mm256_extract_epi64, _mm256_movemask_epi8,
            _mm256_setzero_si256,
        };

        let word_avx2_size_in_word_size = mem::size_of::<__m256i>() / mem::size_of::<u64>();

        let zeroes = _mm256_setzero_si256();

        // DFSan guaratees that, on x86_64, all memory from 0x000000000000 to 0x200000000000 is mapped
        let shadow_page = slice::from_raw_parts(
            shadow_page_ptr.cast::<__m256i>(),
            page_size / size_of::<__m256i>(),
        );

        for (word_avx2_idx, current_word_avx2) in shadow_page.iter().enumerate() {
            let cmp_zero_res = _mm256_cmpeq_epi16(*current_word_avx2, zeroes);
            let cmp_zero_mask = _mm256_movemask_epi8(cmp_zero_res);
            if cmp_zero_mask == -1 {
                // All bytes in the current AVX2 word are zero.
                continue;
            }

            let mask_bytes = cmp_zero_mask.to_ne_bytes();

            if mask_bytes[0] != 0xff {
                let current_word = _mm256_extract_epi64::<0>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 0;
                Self::parse_backed_shadow_word(
                    current_word,
                    current_word_idx,
                    original_base_address,
                    translation_map,
                    tainted_bytes_map,
                );
            }

            if mask_bytes[1] != 0xff {
                let current_word = _mm256_extract_epi64::<1>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 1;
                Self::parse_backed_shadow_word(
                    current_word,
                    current_word_idx,
                    original_base_address,
                    translation_map,
                    tainted_bytes_map,
                );
            }

            if mask_bytes[2] != 0xff {
                let current_word = _mm256_extract_epi64::<2>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 2;
                Self::parse_backed_shadow_word(
                    current_word,
                    current_word_idx,
                    original_base_address,
                    translation_map,
                    tainted_bytes_map,
                );
            }

            if mask_bytes[3] != 0xff {
                let current_word = _mm256_extract_epi64::<3>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 3;
                Self::parse_backed_shadow_word(
                    current_word,
                    current_word_idx,
                    original_base_address,
                    translation_map,
                    tainted_bytes_map,
                );
            }
        }
    }

    fn parse_backed_shadow_word(
        shadow_word: u64,
        word_idx: usize,
        original_base_address: usize,
        translation_map: &BTreeMap<dfsan_label, usize>,
        tainted_bytes_map: &mut BTreeMap<DataPtr, usize>,
    ) {
        for (label_idx, current_label_bytes) in shadow_word
            .to_ne_bytes()
            .chunks_exact(mem::size_of::<dfsan_label>())
            .enumerate()
        {
            let current_label = dfsan_label::from_ne_bytes(current_label_bytes.try_into().unwrap());
            if current_label != 0 {
                let shadow_offset =
                    word_idx * mem::size_of::<u64>() + label_idx * mem::size_of::<dfsan_label>();
                let target_address = original_base_address + shadow_offset / 2;
                tainted_bytes_map.insert(
                    DataPtr::from(target_address as *const u8),
                    translation_map[&current_label],
                );
            }
        }
    }

    fn find_target_frame_cursor(
        target_address: DataPtr,
        unwind_context: Pin<&mut Context>,
    ) -> Result<Cursor, TracerError> {
        let mut target_cursor: Option<Cursor> = None;
        {
            let mut cursor = Cursor::local(unwind_context).context(UnwindFailed)?;
            let mut old_cursor = None;
            loop {
                let stack_ptr =
                    DataPtr::from(cursor.register(RegNum::SP).context(UnwindFailed)? as *const u8);

                if stack_ptr > target_address {
                    target_cursor = old_cursor;

                    if log_enabled!(log::Level::Trace) {
                        let target_stack_ptr = target_cursor
                            .as_mut()
                            .unwrap()
                            .register(RegNum::SP)
                            .context(UnwindFailed)?
                            as *const u8;

                        let next_stack_ptr =
                            cursor.register(RegNum::SP).context(UnwindFailed)? as *const u8;

                        log::trace!(
                            "Target frame: ({:?},{:?})",
                            target_stack_ptr,
                            next_stack_ptr
                        );
                    }

                    break;
                }

                old_cursor = Some(cursor.clone());
                if !cursor.step().context(UnwindFailed)? {
                    break;
                }
            }
        }

        target_cursor.context(FrameNotFound {
            address: target_address,
        })
    }

    fn find_binary_for_function(
        function_entry: *mut c_void,
        process_maps: &[MemoryMap],
    ) -> Result<&Path, TracerError> {
        let code_map = process_maps
            .iter()
            .find(|map| {
                let (start_addr, end_addr) = map.address;
                let target_symbol_address = function_entry as u64;
                start_addr <= target_symbol_address && end_addr > target_symbol_address
            })
            .context(BinaryNotFound {
                address: function_entry,
            })?;
        let (beg_addr, end_addr) = code_map.address;
        log::trace!(
            "Matched code map: ({:#x},{:#x}) {}",
            beg_addr,
            end_addr,
            code_map.perms,
        );

        if !code_map.perms.contains('x') {
            // Code map should be executable
            return BinaryNotFound {
                address: function_entry,
            }
            .fail();
        }

        if let MMapPath::Path(binary_path) = &code_map.pathname {
            Ok(binary_path.as_path())
        } else {
            BinaryNotFound {
                address: function_entry,
            }
            .fail()
        }
    }

    fn resolve_stack_address(
        &mut self,
        target_address: DataPtr,
        process_maps: &[MemoryMap],
    ) -> Result<AddressKind, TracerError> {
        // Only unwinding the stack for the resolution thread is supported.
        get_context!(unwind_context);

        let mut target_frame_cursor =
            Self::find_target_frame_cursor(target_address, unwind_context)?;
        let target_symbol_address = target_frame_cursor
            .procedure_info()
            .context(UnwindFailed)?
            .start_ip() as *mut c_void;

        log::trace!(
            "Target function: ({:?}) {}",
            target_symbol_address,
            target_frame_cursor
                .procedure_name()
                .map(|procedure_name| procedure_name.name().to_string())
                .unwrap_or_else(|_| String::from("unknown"))
        );

        let binary_path = Self::find_binary_for_function(target_symbol_address, process_maps)?;
        log::trace!("Binary path: {}", binary_path.display());

        let llvm_stack_maps = self
            .stack_maps_cache
            .get_stack_map(&binary_path)
            .context(StackMapCacheError)?;

        let mut target_stack_map = None;
        let mut target_function_entry = None;
        let mut stack_maps = llvm_stack_maps.stack_maps();
        'stack_maps_loop: while let Some(stack_map) =
            stack_maps.next().context(StackMapDecodeError)?
        {
            let mut functions = stack_map.functions();
            while let Some(function) = functions.next().context(StackMapDecodeError)? {
                if function.address() as *const c_void == target_symbol_address {
                    target_stack_map = Some(stack_map);
                    target_function_entry = Some(function);
                    break 'stack_maps_loop;
                }
            }
        }
        let target_stack_map = target_stack_map.context(FunctionEntryNotFound {
            address: target_symbol_address,
        })?;
        let target_function_entry = target_function_entry.context(FunctionEntryNotFound {
            address: target_symbol_address,
        })?;

        let mut address_info = None;

        // Records are uniquely identified through their ID
        let mut records = target_function_entry.records();
        'records_loop: while let Some(record) = records.next().context(StackMapDecodeError)? {
            let record_id = record.patch_point_id();

            // The order of locations is guaranteed to be preserved, they are
            // arguments of an intrinsic, so the index can be used as an ID
            let mut locations = record.locations().enumerate();
            while let Some((location_idx, alloca_location)) =
                locations.next().context(StackMapDecodeError)?
            {
                let allocation_base = match alloca_location.kind() {
                    LocationKind::Direct { register, offset } => {
                        let reg_num = match *register {
                            6 => RegNum::RBP,
                            _ => unimplemented!("Location register not supported"),
                        };
                        // It is important to access the register only here
                        // because the stackmap is ensuring that the register I
                        // am trying to access is indeed present.
                        let register_base = DataPtr::from(
                            target_frame_cursor
                                .register(reg_num)
                                .context(UnwindFailed)? as *const u8,
                        );
                        register_base.offset(*offset as isize)
                    },
                    _ => return MismatchedLocationKind.fail(),
                };

                let (_, size_location) = locations
                    .next()
                    .context(StackMapDecodeError)?
                    .context(MismatchedLocationKind)?;
                let allocation_size = match size_location.kind() {
                    LocationKind::Constant(allocation_size) => *allocation_size as usize,
                    _ => return MismatchedLocationKind.fail(),
                };
                let allocation_end = allocation_base.add(allocation_size);
                let allocation = Range {
                    start: allocation_base,
                    end: allocation_end,
                };
                if allocation.contains(&target_address) {
                    log::trace!(
                        "Target allocation: {:?}, {}",
                        allocation_base,
                        allocation_size
                    );

                    let location_offt = target_address.offset_from(allocation_base);
                    assert!(location_offt >= 0);

                    address_info = Some(AddressKind::Stack {
                        record_id,
                        location_idx,
                        location_offt: location_offt as usize,
                        stack_map_num_functions_hint: target_stack_map.num_functions(),
                        stack_map_file_hint: binary_path.to_path_buf(),
                    });

                    break 'records_loop;
                }
            }
        }

        let address_info = address_info.context(LocationNotFound)?;

        Ok(address_info)
    }

    fn resolve_static_address(
        &mut self,
        target_address: DataPtr,
        binary_path: impl AsRef<Path>,
    ) -> Result<Option<AddressKind>, TracerError> {
        let symbols_map = self
            .symbols_cache
            .get_symbols_for_binary(&binary_path)
            .context(SymbolsCacheError)?;
        match symbols_map.get_key_value(&target_address) {
            Some((range, (symbol, symbol_idx))) => {
                log::trace!(
                    "Matched symbol: ({:?},{:?}):{} {}({})",
                    range.start,
                    range.end,
                    range.end.offset_from(range.start),
                    symbol,
                    symbol_idx
                );
                Ok(Some(AddressKind::Static {
                    symbol: symbol.clone(),
                    symbol_idx: *symbol_idx,
                    offset: target_address.offset_from(range.start) as usize,
                    binary_path: binary_path.as_ref().to_path_buf(),
                }))
            },
            None => Ok(None),
        }
    }

    fn resolve_heap_address(
        &self,
        target_address: DataPtr,
        heap_map: &RangeMap<DataPtr, AllocID>,
    ) -> Option<AddressKind> {
        heap_map
            .get_key_value(&target_address)
            .map(|(alloc_range, alloc_id)| AddressKind::Heap {
                id: *alloc_id,
                size: alloc_range.end.offset_from(alloc_range.start) as usize,
                offset: target_address.offset_from(alloc_range.start) as usize,
            })
    }

    fn resolve_address(
        &mut self,
        target_address: DataPtr,
        memory_maps: &[MemoryMap],
        heap_map: &RangeMap<DataPtr, AllocID>,
    ) -> Result<AddressKind, TracerError> {
        log::trace!("Resolving address: {:?}", target_address);

        let (target_map_idx, target_map) = memory_maps
            .iter()
            .enumerate()
            .find(|(_, map)| {
                let (start_addr, end_addr) = map.address;
                let start_addr = start_addr as *const u8;
                let end_addr = end_addr as *const u8;
                start_addr <= target_address.into() && end_addr > target_address.into()
            })
            .context(MapNotFound {
                address: target_address,
            })?;

        let (start_addr, end_addr) = target_map.address;
        log::trace!("Resolved to map ({:#x},{:#x})", start_addr, end_addr);

        match &target_map.pathname {
            MMapPath::Stack => {
                log::trace!("Resolving as stack address");
                self.resolve_stack_address(target_address, memory_maps)
            },
            MMapPath::TStack(_thread_id) => {
                // Supported only until Linux 4.4
                log::trace!("Resolving as thread stack address");
                self.resolve_stack_address(target_address, memory_maps)
            },
            MMapPath::Path(binary_path) => {
                log::trace!("Resolving as static variable");
                self.resolve_static_address(target_address, binary_path)?
                    .map_or(SymbolNotFound.fail(), Ok)
            },
            MMapPath::Anonymous => {
                // Check if it is a thread stack
                let x = 42;
                let stack_ref = &x;
                let stack_ptr = stack_ref as *const i32;
                if (stack_ptr as u64) >= start_addr && (stack_ptr as u64) < end_addr {
                    // The stack for this thread is the anonymous map
                    log::trace!("Resolving as thread stack address");
                    return self.resolve_stack_address(target_address, memory_maps);
                }

                // Check if it is an extension of a previous map for .bss
                if let Some(prev_idx) = target_map_idx.checked_sub(1) {
                    let prev_map = memory_maps.get(prev_idx).unwrap();
                    let (_, prev_map_end) = prev_map.address;
                    if prev_map_end == start_addr {
                        if let MMapPath::Path(binary_path) = &prev_map.pathname {
                            if let Some(symbol) =
                                self.resolve_static_address(target_address, binary_path)?
                            {
                                log::trace!("Associated static symbol found: {:?}", symbol);
                                return Ok(symbol);
                            } else {
                                log::trace!("No matching static symbol found");
                            }
                        }
                    }
                }

                unimplemented!("Unsupported generic anonymous map");
            },
            MMapPath::Heap => {
                if let Some(alloc_info) = self.resolve_heap_address(target_address, heap_map) {
                    log::trace!("Associated heap allocation found: {:?}", alloc_info);
                    return Ok(alloc_info);
                } else {
                    log::trace!("No matching heap allocation found");
                }

                // An uninitialized .bss symbol could also end up in the sbrk
                // segment, marked as heap, when ASLR is disabled
                log::trace!("Attempting resolution as static variable");
                if let Some(prev_idx) = target_map_idx.checked_sub(1) {
                    let prev_map = memory_maps.get(prev_idx).unwrap();
                    let (_, prev_map_end) = prev_map.address;
                    if prev_map_end == start_addr {
                        if let MMapPath::Path(binary_path) = &prev_map.pathname {
                            if let Some(symbol) =
                                self.resolve_static_address(target_address, binary_path)?
                            {
                                log::trace!("Associated static symbol found: {:?}", symbol);
                                return Ok(symbol);
                            } else {
                                log::trace!("No matching static symbol found");
                            }
                        }
                    }
                }

                // This may happen when a freed heap allocation is still tainted.
                return HeapAllocationMismatch.fail();
            },
            path => unimplemented!("Unsupported map type: {:?}", path),
        }
    }

    pub fn report_tainted_load(&mut self) -> Result<(), TracerError> {
        // Always fail when a tainted load is detected before performing the snapshot
        TaintedLoadDetected.fail()
    }

    pub fn record_snapshot(&mut self) -> Result<(), TracerError> {
        heap_tracer::with_tracer_disabled(|| {
            let output_path = if let Some(output_path) = self.output_path_opt.as_ref() {
                output_path.clone()
            } else {
                log::debug!("Instrumentation disabled");
                return Ok(());
            };

            if log_enabled!(log::Level::Trace) {
                log::trace!("Recording snapshot at:");
                let backtrace = Backtrace::new();
                self.log_backtrace(&backtrace);
            }

            let start_snapshot = Instant::now();

            let process = Process::myself().context(ProcfsError)?;
            let current_maps = process.maps().context(ProcfsError)?;
            let end_maps = Instant::now();

            let tainted_bytes = self.record_tainted_bytes(&current_maps)?;
            let end_tainted_bytes = Instant::now();

            let heap_map = self.heap_tracer.export_range_map();
            let end_heap_export = Instant::now();

            log::info!("Collecting maps took: {:?}", end_maps - start_snapshot);
            log::info!(
                "Collecting tainted bytes took: {:?}",
                end_tainted_bytes - end_maps
            );
            log::info!(
                "Exporting heap map took: {:?}",
                end_heap_export - end_tainted_bytes
            );
            log::debug!(
                "Heap allocations observed: {}",
                self.heap_tracer.get_allocations_count()
            );

            let mut resolved_tainted_bytes = Vec::with_capacity(tainted_bytes.len());
            for (address, offset) in tainted_bytes {
                let start_resolution = Instant::now();

                let address_info = match self.resolve_address(address, &current_maps, &heap_map) {
                    Ok(address_info) => address_info,
                    Err(error) => match error {
                        TracerError::FunctionEntryNotFound { address: _ }
                        | TracerError::LocationNotFound
                        | TracerError::StackMapCacheError {
                            source: stack_map_cache::Error::StackMapsSectionNotFound { path: _ },
                        } => {
                            log::warn!("Stack address does not match any allocation (saved register or spill?): {}", error);
                            continue;
                        },
                        TracerError::HeapAllocationMismatch => {
                            log::warn!("Heap address does not match any allocation (freed allocation still tainted?): {:?}", address);
                            continue;
                        },
                        _ => return Err(error),
                    },
                };

                let end_resolution = Instant::now();
                log::info!("Resolution took: {:?}", end_resolution - start_resolution);

                resolved_tainted_bytes.push((address_info, offset));
            }

            log::info!("Writing backtrace symbols to file");
            let mut output_file =
                BufWriter::new(File::create(output_path).context(OpenOutputError)?);
            serde_json::to_writer_pretty(output_file.by_ref(), &resolved_tainted_bytes)
                .context(OutputWriteError)?;
            output_file.flush().context(FileFlushError)?;

            Ok(())
        })
    }
}

// This type represents a pointer that cannot be dereferenced, it is used
// only to represent address ranges
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

#[derive(Debug, Serialize, PartialEq, Eq, Hash)]
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

#[derive(Default)]
pub struct TracerBuilder {
    output_path_opt: Option<PathBuf>,
    snapshot_target_path: Option<PathBuf>,
    stack_maps_cache: Option<StackMapCache>,
    symbols_cache: Option<SymbolsCache>,
}

impl TracerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn output_file(&mut self, file_path: PathBuf) -> &mut Self {
        self.output_path_opt = Some(file_path);
        self
    }

    pub fn snapshot_target_path(&mut self, snapshot_target_path: PathBuf) -> &mut Self {
        self.snapshot_target_path = Some(snapshot_target_path);
        self
    }

    pub fn stack_maps_cache(&mut self, stack_maps_cache: StackMapCache) -> &mut Self {
        self.stack_maps_cache = Some(stack_maps_cache);
        self
    }

    pub fn symbols_cache(&mut self, symbols_cache: SymbolsCache) -> &mut Self {
        self.symbols_cache = Some(symbols_cache);
        self
    }

    pub fn build_global(self) -> Result<(), TracerError> {
        let snapshot_target_path = self
            .snapshot_target_path
            .context(MissingSnapshotTargetPath)?;

        let snapshot_target_deserialization_begin = Instant::now();
        let snapshot_target_file =
            File::open(snapshot_target_path).context(OpenSnapshotFileFailed)?;
        let snapshot_target_reader = BufReader::new(snapshot_target_file);

        let snapshot_target_dump: SnapshotTargetDump =
            serde_json::from_reader(snapshot_target_reader).context(SnapshotTargetDecodeFailed)?;
        let snapshot_target = snapshot_target_dump.into_snapshot_target()?;
        log::debug!(
            "Snapshot target deserialization took: {:?}",
            snapshot_target_deserialization_begin.elapsed()
        );

        let tracer = if let Some(output_path) = self.output_path_opt {
            Tracer {
                output_path_opt: Some(output_path),
                snapshot_target: Some(snapshot_target),
                stack_maps_cache: self.stack_maps_cache.unwrap_or_default(),
                symbols_cache: self.symbols_cache.unwrap_or_default(),
                ..Default::default()
            }
        } else {
            log::info!("Tracer disabled");
            Default::default()
        };

        ensure!(TRACER.set(Mutex::new(tracer)).is_ok(), AlreadyExists);

        Ok(())
    }
}

#[derive(Deserialize, Default)]
pub struct SnapshotTargetDump {
    target_ids: Vec<FunctionID>,
    target_kind: String,
    hit_count: usize,
}

impl SnapshotTargetDump {
    // This function is necessary because I have not found a way to implement
    // Deserialize for XRayEntryType.
    pub fn into_snapshot_target(self) -> Result<SnapshotTarget, TracerError> {
        let target_kind = match self.target_kind.as_str() {
            "ENTRY" => XRayEntryType::ENTRY,
            "EXIT" => XRayEntryType::EXIT,
            "TAIL" => XRayEntryType::EXIT, // Match the code in XRaySnapshotRT.
            kind => {
                return InvalidTargetKind {
                    kind: kind.to_string(),
                }
                .fail()
            },
        };

        Ok(SnapshotTarget {
            target_ids: self.target_ids,
            target_kind,
            hit_count: self.hit_count,
        })
    }
}

#[derive(Clone)]
pub struct SnapshotTarget {
    target_ids: Vec<FunctionID>,
    target_kind: XRayEntryType,
    hit_count: usize,
}

impl SnapshotTarget {
    pub fn target_ids(&self) -> &[FunctionID] {
        &self.target_ids
    }

    pub fn hit_count(&self) -> usize {
        self.hit_count
    }

    pub fn target_kind(&self) -> XRayEntryType {
        self.target_kind
    }
}

#[derive(Debug, Snafu)]
pub enum TracerError {
    #[snafu(display("Tracer has already been instantiated"))]
    AlreadyExists,
    #[snafu(display("Could not open output file: {}", source))]
    OpenOutputError {
        source: io::Error,
    },
    #[snafu(display("Could not write to output file: {}", source))]
    OutputWriteError {
        source: serde_json::Error,
    },
    #[snafu(display("Could not flush output file: {}", source))]
    FileFlushError {
        source: io::Error,
    },
    #[snafu(display("Could not retrieve caller frame"))]
    NoCallerFrame,
    #[snafu(display("Could not retrieve data from procfs: {}", source))]
    ProcfsError {
        source: procfs::ProcError,
    },
    #[snafu(display("Could not retrieve page size: {}", source))]
    PageSizeError {
        source: io::Error,
    },
    MapNotFound {
        address: *const u8,
    },
    FrameNotFound {
        address: *const u8,
    },
    BinaryNotFound {
        address: *mut c_void,
    },
    StackMapCacheError {
        source: stack_map_cache::Error,
    },
    StackMapDecodeError {
        source: stackmap::Error,
    },
    #[snafu(display("Could not find entry for function in stack map: {:?}", address))]
    FunctionEntryNotFound {
        address: *mut c_void,
    },
    MismatchedLocationKind,
    LocationNotFound,
    SymbolsCacheError {
        source: symbols_cache::Error,
    },
    SymbolNotFound,
    HeapAllocationMismatch,
    #[snafu(display("Could not unwind stack: {}", source))]
    UnwindFailed {
        source: unwind::Error,
    },
    MissingHitCount,
    InvalidTargetKind {
        kind: String,
    },
    MismatchedHook,
    #[snafu(display("A tainted load was detected before performing the snapshot"))]
    TaintedLoadDetected,
    PatchFailed {
        function_id: FunctionID,
        status: XRayPatchingStatus,
    },
    MissingSnapshotTargetPath,
    OpenSnapshotFileFailed {
        source: std::io::Error,
    },
    SnapshotTargetDecodeFailed {
        source: serde_json::Error,
    },
}
