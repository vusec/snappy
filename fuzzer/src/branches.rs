use crate::executor::StatusType;
use angora_common::{config::BRANCHES_SIZE, shm::SHM};
use sprs::CsVec;
use std::{
    self, io,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    ptr, slice,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock, RwLockReadGuard, RwLockWriteGuard,
    },
};

pub type BranchBuf = [u8; BRANCHES_SIZE];

#[cfg(target_pointer_width = "32")]
type BranchWord = u32;
#[cfg(target_pointer_width = "64")]
type BranchWord = u64;
const ENTRY_SIZE: usize = mem::size_of::<BranchWord>();
type BranchBufWords = [BranchWord; BRANCHES_SIZE / ENTRY_SIZE];

// Map of bit bucket
// [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
const COUNT_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
type MapsBuffer = [BranchBuf; 3];

pub struct GlobalBranches {
    maps_buffer: *mut MapsBuffer,
    maps_buffer_size: usize,

    virgin_ptr: RwLock<*mut BranchBuf>,
    tmouts_ptr: RwLock<*mut BranchBuf>,
    crashes_ptr: RwLock<*mut BranchBuf>,

    density: AtomicUsize,
}

unsafe impl Send for GlobalBranches {}
unsafe impl Sync for GlobalBranches {}

impl<'a> GlobalBranches {
    pub fn new() -> Self {
        let (maps_buffer, maps_buffer_size) = match Self::allocate_buffer_with_huge_pages() {
            Ok(maps_info) => maps_info,
            Err(error) => {
                log::warn!(
                    "Using normal pages, huge pages could not be allocated: {}",
                    error
                );

                match Self::allocate_buffer_with_normal_pages() {
                    Ok(maps_info) => maps_info,
                    Err(error) => panic!("Could not allocate global maps: {}", error),
                }
            },
        };

        unsafe {
            for map in &mut *maps_buffer {
                map.fill(0xff);
            }
        }

        let virgin_ptr = unsafe { &mut (*maps_buffer)[0] };
        let tmouts_ptr = unsafe { &mut (*maps_buffer)[0] };
        let crashes_ptr = unsafe { &mut (*maps_buffer)[0] };

        Self {
            maps_buffer,
            maps_buffer_size,

            virgin_ptr: RwLock::new(virgin_ptr),
            tmouts_ptr: RwLock::new(tmouts_ptr),
            crashes_ptr: RwLock::new(crashes_ptr),

            density: AtomicUsize::new(0),
        }
    }

    fn allocate_buffer_with_huge_pages() -> io::Result<(*mut MapsBuffer, usize)> {
        // The size of the mmap should be rounded to the size of a hugepage
        let maps_buffer_size = (mem::size_of::<MapsBuffer>() / HUGE_PAGE_SIZE + 1) * HUGE_PAGE_SIZE;

        let maps_buffer;
        unsafe {
            maps_buffer = libc::mmap(
                ptr::null_mut(),
                maps_buffer_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                -1,
                0,
            );
        }
        if maps_buffer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok((maps_buffer.cast(), maps_buffer_size))
    }

    fn allocate_buffer_with_normal_pages() -> io::Result<(*mut MapsBuffer, usize)> {
        let maps_buffer_size = mem::size_of::<MapsBuffer>();

        let maps_buffer;
        unsafe {
            maps_buffer = libc::mmap(
                ptr::null_mut(),
                maps_buffer_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
        }
        if maps_buffer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok((maps_buffer.cast(), maps_buffer_size))
    }

    pub fn virgin_branches(&self) -> BranchesReadView {
        BranchesReadView {
            guard: self.virgin_ptr.read().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn virgin_branches_mut(&self) -> BranchesWriteView {
        BranchesWriteView {
            guard: self.virgin_ptr.write().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn tmouts_branches(&self) -> BranchesReadView {
        BranchesReadView {
            guard: self.tmouts_ptr.read().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn tmouts_branches_mut(&self) -> BranchesWriteView {
        BranchesWriteView {
            guard: self.tmouts_ptr.write().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn crashes_branches(&self) -> BranchesReadView {
        BranchesReadView {
            guard: self.crashes_ptr.read().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn crashes_branches_mut(&self) -> BranchesWriteView {
        BranchesWriteView {
            guard: self.crashes_ptr.write().unwrap(),
            phantom: PhantomData,
        }
    }

    pub fn get_density(&self) -> f32 {
        let d = self.density.load(Ordering::Relaxed);
        (d * 10000 / BRANCHES_SIZE) as f32 / 100.0
    }
}

impl Drop for GlobalBranches {
    fn drop(&mut self) {
        unsafe {
            let res = libc::munmap(self.maps_buffer.cast(), self.maps_buffer_size);
            if res == -1 {
                let error = io::Error::last_os_error();
                panic!(
                    "munmap({:?}, {}): {}",
                    self.maps_buffer, self.maps_buffer_size, error
                );
            }
        }
    }
}

pub struct BranchesReadView<'a> {
    guard: RwLockReadGuard<'a, *mut BranchBuf>,
    phantom: PhantomData<&'a BranchBuf>,
}

impl<'a> Deref for BranchesReadView<'a> {
    type Target = BranchBuf;

    fn deref(&self) -> &Self::Target {
        unsafe { &**self.guard }
    }
}

pub struct BranchesWriteView<'a> {
    guard: RwLockWriteGuard<'a, *mut BranchBuf>,
    phantom: PhantomData<&'a mut BranchBuf>,
}

impl<'a> Deref for BranchesWriteView<'a> {
    type Target = BranchBuf;

    fn deref(&self) -> &Self::Target {
        unsafe { &**self.guard }
    }
}

impl<'a> DerefMut for BranchesWriteView<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut **self.guard }
    }
}

pub struct Branches {
    global: Arc<GlobalBranches>,
    trace: SHM<BranchBuf>,
}

impl Branches {
    pub fn new(global: Arc<GlobalBranches>) -> Self {
        let trace = SHM::<BranchBuf>::new_huge();
        Self { global, trace }
    }

    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    pub fn get_id(&self) -> i32 {
        self.trace.get_id()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn has_new_path_avx2(
        virgin_map: &BranchBuf,
        current_map: &mut BranchBuf,
        should_clear: bool,
    ) -> bool {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::{
            __m256i, _mm256_cmpeq_epi8, _mm256_extract_epi64, _mm256_movemask_epi8,
            _mm256_setzero_si256,
        };
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{
            __m256i, _mm256_cmpeq_epi8, _mm256_extract_epi64, _mm256_movemask_epi8,
            _mm256_setzero_si256,
        };

        let word_avx2_size_in_word_size = mem::size_of::<__m256i>() / mem::size_of::<BranchWord>();

        let zeroes = _mm256_setzero_si256();

        let current_map_words_avx2 = slice::from_raw_parts_mut(
            current_map.as_mut_ptr().cast::<__m256i>(),
            BRANCHES_SIZE / mem::size_of::<__m256i>(),
        );

        for (word_avx2_idx, current_word_avx2) in current_map_words_avx2.iter_mut().enumerate() {
            let cmp_zero_res = _mm256_cmpeq_epi8(*current_word_avx2, zeroes);
            let cmp_zero_mask = _mm256_movemask_epi8(cmp_zero_res);
            if cmp_zero_mask == -1 {
                // All bytes in the current AVX2 word are zero.
                continue;
            }

            let mask_bytes = cmp_zero_mask.to_ne_bytes();

            if mask_bytes[0] != 0xff {
                let current_word = _mm256_extract_epi64::<0>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 0;
                if Self::has_new_path_word(virgin_map, current_word, current_word_idx) {
                    return true;
                }
            }

            if mask_bytes[1] != 0xff {
                let current_word = _mm256_extract_epi64::<1>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 1;
                if Self::has_new_path_word(virgin_map, current_word, current_word_idx) {
                    return true;
                }
            }

            if mask_bytes[2] != 0xff {
                let current_word = _mm256_extract_epi64::<2>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 2;
                if Self::has_new_path_word(virgin_map, current_word, current_word_idx) {
                    return true;
                }
            }

            if mask_bytes[3] != 0xff {
                let current_word = _mm256_extract_epi64::<3>(*current_word_avx2) as u64;
                let current_word_idx = word_avx2_idx * word_avx2_size_in_word_size + 3;
                if Self::has_new_path_word(virgin_map, current_word, current_word_idx) {
                    return true;
                }
            }

            // If this location is reached, at least one byte in the AVX2 word
            // was not zero, but no new coverage was found. If this is the case,
            // just zero the whole word out, so either we end up with a zeroed
            // coverage map, or we hit the fast path in
            // `get_sparse_classified_branches` more often
            if should_clear {
                *current_word_avx2 = zeroes;
            }
        }

        return false;
    }

    fn has_new_path_word(
        virgin_map: &BranchBuf,
        current_word: BranchWord,
        word_idx: usize,
    ) -> bool {
        for (byte_idx, &current_byte) in current_word.to_ne_bytes().iter().enumerate() {
            let classified_byte = COUNT_LOOKUP[current_byte as usize];
            let map_relative_byte_idx = word_idx * ENTRY_SIZE + byte_idx;
            if classified_byte & virgin_map[map_relative_byte_idx] != 0 {
                return true;
            }
        }

        return false;
    }

    fn has_new_path(
        virgin_map: &BranchBuf,
        current_map: &mut BranchBuf,
        should_clear: bool,
    ) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                return unsafe { Self::has_new_path_avx2(virgin_map, current_map, should_clear) };
            }
        }

        let current_map_words: &mut BranchBufWords = unsafe { mem::transmute(current_map) };

        for (word_idx, current_word) in current_map_words.iter_mut().enumerate() {
            if *current_word > 0 {
                if Self::has_new_path_word(virgin_map, *current_word, word_idx) {
                    return true;
                } else if should_clear {
                    *current_word = 0;
                }
            }
        }

        return false;
    }

    fn get_sparse_classified_branches(
        current_map: &mut BranchBuf,
        should_clear: bool,
    ) -> CsVec<u8> {
        let mut sparse_branches = CsVec::empty(BRANCHES_SIZE);

        let current_map_words: &mut BranchBufWords = unsafe { mem::transmute(current_map) };

        for (word_idx, current_word) in current_map_words.iter_mut().enumerate() {
            if *current_word > 0 {
                for (byte_idx, &current_byte) in current_word.to_ne_bytes().iter().enumerate() {
                    if current_byte > 0 {
                        let classified_byte = COUNT_LOOKUP[current_byte as usize];
                        let map_relative_byte_idx = word_idx * ENTRY_SIZE + byte_idx;

                        sparse_branches.append(map_relative_byte_idx, classified_byte);
                    }
                }

                if should_clear {
                    *current_word = 0;
                }
            }
        }

        sparse_branches
    }

    /// Returns information on the trace of the last test case that was run:
    /// 1. Whether it followed a path that was not seen before.
    /// 1. Whether it touched at least one edge that was not touched before.
    /// 2. Optionally, the total number of edges in the current path (lower
    ///    bound).
    pub fn has_new(
        &mut self,
        status: StatusType,
        should_clear: bool,
    ) -> (bool, bool, Option<usize>) {
        let mut bytes_to_update;
        let num_current_edges;
        let mut num_new_edges;
        {
            let global_map_read = match status {
                StatusType::Normal => self.global.virgin_branches(),
                StatusType::Timeout => self.global.tmouts_branches(),
                StatusType::Crash => self.global.crashes_branches(),
                _ => unreachable!(),
            };

            // If the current trace did not follow a new path, return
            // immediately. This is the most common case.
            if !Self::has_new_path(&global_map_read, &mut self.trace, should_clear) {
                return (false, false, None);
            }

            let path = Self::get_sparse_classified_branches(&mut self.trace, should_clear);
            num_current_edges = path.nnz();

            bytes_to_update = CsVec::empty(BRANCHES_SIZE);
            num_new_edges = 0;
            for (byte_idx, &current_classified_byte) in path.iter() {
                let global_map_byte = global_map_read[byte_idx];

                if global_map_byte == 255u8 {
                    num_new_edges += 1;
                }

                if (current_classified_byte & global_map_byte) > 0 {
                    bytes_to_update.append(byte_idx, global_map_byte & (!current_classified_byte));
                }
            }
        }

        // There should be at least one byte to update in the global map since
        // the current trace followed a new path.
        assert!(!bytes_to_update.nnz() > 0);

        if num_new_edges > 0 {
            if status == StatusType::Normal {
                // only count virgin branches
                self.global
                    .density
                    .fetch_add(num_new_edges, Ordering::Relaxed);
            }
        }

        {
            // Lock and update global map
            let mut global_map_write = match status {
                StatusType::Normal => self.global.virgin_branches_mut(),
                StatusType::Timeout => self.global.tmouts_branches_mut(),
                StatusType::Crash => self.global.crashes_branches_mut(),
                _ => unreachable!(),
            };

            for (idx, &byte_to_write) in bytes_to_update.iter() {
                global_map_write[idx] = byte_to_write;
            }
        }

        (true, num_new_edges > 0, Some(num_current_edges))
    }
}

impl std::fmt::Debug for Branches {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coverage_map_no_coverage() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);
        assert_eq!(br.has_new(StatusType::Normal, false), (false, false, None));
        assert_eq!(br.has_new(StatusType::Timeout, false), (false, false, None));
        assert_eq!(br.has_new(StatusType::Crash, false), (false, false, None));
    }

    #[test]
    fn parse_coverage_map_new_coverage() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);

        let trace = &mut br.trace;
        trace[4] = 1;
        trace[5] = 1;
        trace[8] = 3;

        let path = Branches::get_sparse_classified_branches(&mut br.trace, false);
        assert_eq!(path.nnz(), 3);
        assert_eq!(path.data()[2], COUNT_LOOKUP[3]);

        assert_eq!(br.has_new(StatusType::Normal, false), (true, true, Some(3)));
    }

    #[test]
    fn parse_coverage_map_no_new_coverage() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);

        let trace = &mut br.trace;
        trace[4] = 1;
        trace[5] = 1;
        trace[8] = 3;

        br.has_new(StatusType::Normal, false);

        assert_eq!(br.has_new(StatusType::Normal, false), (false, false, None));
    }

    #[test]
    fn parse_coverage_map_reset_new_coverage() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);

        let trace = &mut br.trace;
        trace[4] = 1;
        trace[5] = 1;
        trace[8] = 3;

        assert_eq!(br.has_new(StatusType::Normal, true), (true, true, Some(3)));

        let trace = &br.trace;
        assert!(trace.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parse_coverage_map_reset_no_new_coverage() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);

        let trace = &mut br.trace;
        trace[4] = 1;
        trace[5] = 1;
        trace[8] = 3;

        br.has_new(StatusType::Normal, false);

        assert_eq!(br.has_new(StatusType::Normal, true), (false, false, None));

        let trace = &br.trace;
        assert!(trace.iter().all(|byte| *byte == 0));
    }
}
