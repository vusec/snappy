use crate::{
    dfsan::{dfsan_create_label, dfsan_label, dfsan_set_label},
    heap_tracer,
};
use once_cell::sync::OnceCell;
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::{raw::c_void, unix::io::RawFd},
    path::{Path, PathBuf},
    ptr,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

static TAINTER: OnceCell<Mutex<Tainter>> = OnceCell::new();

#[derive(Default)]
pub struct Tainter {
    canonical_path_opt: Option<PathBuf>,

    tainted_file_descriptors: BTreeSet<RawFd>,
    taint_info: TaintInfo,

    label_manager: LabelManager,
}

#[derive(Default)]
pub struct LabelManager {
    offsets_to_labels: BTreeMap<usize, dfsan_label>,
    labels_to_offsets: BTreeMap<dfsan_label, usize>,
}

impl LabelManager {
    fn get_or_create_label(&mut self, offset: usize) -> dfsan_label {
        if let Some(label) = self.offsets_to_labels.get(&offset) {
            *label
        } else {
            log::trace!("Creating label for offset: {}", offset);

            // Trust dfsan to create the label correctly, or die
            let new_label = unsafe { dfsan_create_label(ptr::null(), ptr::null_mut()) };
            self.offsets_to_labels.insert(offset, new_label);
            self.labels_to_offsets.insert(new_label, offset);
            new_label
        }
    }

    fn get_labels_to_offsets_map(&self) -> &BTreeMap<dfsan_label, usize> {
        &self.labels_to_offsets
    }
}

impl Tainter {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        heap_tracer::with_tracer_disabled(|| {
            let lock = TAINTER.get()?;
            Some(lock.lock().unwrap())
        })
    }

    pub fn trace_open(&mut self, fd: RawFd, current_path: impl AsRef<Path>) {
        heap_tracer::with_tracer_disabled(|| {
            let tainted_path = if let Some(tainted_path) = self.canonical_path_opt.as_ref() {
                tainted_path
            } else {
                // Instrumentation disabled
                return;
            };

            // Canonicalize may fail. In that case, ignore the error, open should have failed anyway.
            let canonical_current_path =
                if let Ok(canonical_current_path) = current_path.as_ref().canonicalize() {
                    canonical_current_path
                } else {
                    return;
                };

            if tainted_path == &canonical_current_path {
                log::debug!(
                    "Matching file detected: {}",
                    canonical_current_path.display()
                );
                log::debug!("File descriptor: {}", fd);
                self.tainted_file_descriptors.insert(fd);
            }
        })
    }

    /// Taint the whole range starting from `addr` for `size` bytes using labels starting at `offset`
    fn taint_range(&mut self, addr: *mut c_void, offset: usize, size: usize) {
        for idx in 0..size {
            let idx_label = self.label_manager.get_or_create_label(offset + idx);
            // addr + idx is guaranteed to stay within the range that was read. If it does not,
            // there is a bug in one of the wrappers
            unsafe { dfsan_set_label(idx_label, addr.add(idx), 1) };
        }
    }

    /// Remove taints from the range starting from `addr` for `size` bytes
    fn untaint_range(&self, addr: *mut c_void, size: usize) {
        unsafe { dfsan_set_label(0, addr, size) }
    }

    pub fn trace_read(
        &mut self,
        file_descriptor: RawFd,
        addr: *mut c_void,
        file_offset: usize,
        read_size: usize,
    ) {
        heap_tracer::with_tracer_disabled(|| {
            if !self.tainted_file_descriptors.contains(&file_descriptor) {
                // Not target file, zero out all labels
                unsafe { dfsan_set_label(0, addr, read_size) };
                return;
            }

            log::debug!(
                "Read from tainted file: [{}, {})",
                file_offset,
                file_offset + read_size
            );

            let tainted_offsets = match &self.taint_info {
                TaintInfo::AllTainted => {
                    // The whole file is tainted, so just taint all the bytes that
                    // were read with the appropriate labels
                    self.taint_range(addr, file_offset, read_size);
                    return;
                },
                TaintInfo::TaintedOffsets(tainted_offsets) => tainted_offsets,
            };

            // The remainder assumes that `tainted_offsets` is sorted

            let lower_bound = *tainted_offsets.first().unwrap();
            let upper_bound = *tainted_offsets.last().unwrap();
            if upper_bound < file_offset || lower_bound >= file_offset + read_size {
                log::trace!("Non overlapping read, untainting.");

                // Ranges do not overlap, the read is either before or after all the
                // tainted bytes
                self.untaint_range(addr, read_size);
                return;
            }

            // A read includes all the offsets in `[offset, offset + size)`, so all
            // the tainted offsets between those two values taint the read.
            let begin_range_pos_res = tainted_offsets.binary_search(&file_offset);
            let relevant_tainted_offsets_start =
                begin_range_pos_res.unwrap_or_else(|offset| offset);

            let last_read_offset = file_offset + read_size - 1;
            let end_range_pos_res = tainted_offsets.binary_search(&last_read_offset);
            let relevant_tainted_offsets_end = end_range_pos_res.unwrap_or_else(|offset| {
                // If the read offset is found, keep it, if it is not, exclude it,
                // thus the -1. This index is included in the slice.
                offset - 1
            });

            let relevant_tainted_offsets =
                &tainted_offsets[relevant_tainted_offsets_start..=relevant_tainted_offsets_end];

            log::trace!("Relevant offsets: {:?}", relevant_tainted_offsets);

            // Iterate through the target buffer and taint each byte with the
            // correct label if it is in the `tainted_offsets` vector. All the
            // tainted offsets in [`offset`, `offset + size`) should taint one byte,
            // the other bytes should be untainted.
            //
            // Since the `relevant_tainted_offsets` slice is ordered, the offsets of
            // the bytes to be tainted should be encountered in order as well. No
            // need to search for each single one of them, an iterator is used to
            // keep track of what was used.
            let mut relevant_tainted_offsets_iter = relevant_tainted_offsets.iter().peekable();
            for read_offset in 0..read_size {
                if let Some(next_relevant_tainted_offset) = relevant_tainted_offsets_iter.peek() {
                    // There is a relevant tainted offset still to be matched

                    let current_file_offset = read_offset + file_offset;
                    if **next_relevant_tainted_offset == current_file_offset {
                        // The current file offset is tainted

                        let offset_label =
                            self.label_manager.get_or_create_label(current_file_offset);

                        log::trace!("Tainted offset matched: {}", current_file_offset);

                        // addr + read_offset is guaranteed to stay within the range
                        // that was read. If it does not, there is a bug in one of the
                        // wrappers
                        unsafe { dfsan_set_label(offset_label, addr.add(read_offset), 1) };

                        // The current file offset was used, so advance the iterator
                        relevant_tainted_offsets_iter.next();
                    } else {
                        // The current file offset is not in `tainted_offsets`

                        // addr + read_offset is guaranteed to stay within the range
                        // that was read. If it does not, there is a bug in one of the
                        // wrappers
                        unsafe { dfsan_set_label(0, addr.add(read_offset), 1) };
                    }
                } else {
                    // There is no relevant tainted offset left to use

                    // addr + read_offset is guaranteed to stay within the range
                    // that was read. If it does not, there is a bug in one of the
                    // wrappers
                    unsafe { dfsan_set_label(0, addr.add(read_offset), 1) };
                }
            }

            // The relevant tainted offsets should be finished by when the taints
            // have all been set
            assert!(relevant_tainted_offsets_iter.peek().is_none());
        })
    }

    pub fn get_byte_label(&mut self, fd: RawFd, offset: usize) -> Option<dfsan_label> {
        heap_tracer::with_tracer_disabled(|| {
            if !self.tainted_file_descriptors.contains(&fd) {
                // Not target file
                return None;
            }

            if let TaintInfo::TaintedOffsets(tainted_offsets) = &self.taint_info {
                if tainted_offsets.binary_search(&offset).is_err() {
                    // Byte is not tainted
                    return None;
                }
            }

            Some(self.label_manager.get_or_create_label(offset))
        })
    }

    pub fn trace_close(&mut self, fd: RawFd) {
        heap_tracer::with_tracer_disabled(|| {
            if self.tainted_file_descriptors.remove(&fd) {
                log::debug!("Removed file descriptor: {}", fd);
            }
        })
    }

    pub fn get_translation_map(&self) -> &BTreeMap<dfsan_label, usize> {
        heap_tracer::with_tracer_disabled(|| self.label_manager.get_labels_to_offsets_map())
    }
}

pub struct TainterBuilder {
    tainted_path_opt: Option<PathBuf>,
    tainted_offsets_path_opt: Option<PathBuf>,
    all_tainted: bool,
}

impl TainterBuilder {
    pub fn new() -> Self {
        Self {
            tainted_path_opt: None,
            tainted_offsets_path_opt: None,
            all_tainted: false,
        }
    }

    pub fn taint_file(&mut self, file_path: PathBuf) -> &mut Self {
        self.tainted_path_opt = Some(file_path);
        self
    }

    pub fn tainted_offsets_file(&mut self, file_path: PathBuf) -> &mut Self {
        self.tainted_offsets_path_opt = Some(file_path);
        self
    }

    pub fn all_tainted(&mut self) -> &mut Self {
        self.all_tainted = true;
        self
    }

    pub fn build_global(self) -> Result<(), TainterError> {
        let canonical_path_opt = if let Some(tainted_path) = self.tainted_path_opt {
            let canonicalization_start = Instant::now();
            let canonical_path = tainted_path
                .canonicalize()
                .context(InvalidTaintPath { path: tainted_path })?;
            log::debug!(
                "Canonicalization took: {:?}",
                canonicalization_start.elapsed()
            );

            log::info!("Tainted file: {}", canonical_path.display());
            Some(canonical_path)
        } else {
            log::info!("No tainted file, instrumentation disabled");
            None
        };

        let taint_info = if self.all_tainted {
            if self.tainted_offsets_path_opt.is_some() {
                log::warn!("Tainted offsets file specified when all input is tainted");
            }

            TaintInfo::AllTainted
        } else if canonical_path_opt.is_some() {
            // The tainter is enabled, so require a offsets file

            let tainted_offsets_path = self
                .tainted_offsets_path_opt
                .context(MissingTaintedOffsetsPath)?;

            let tainted_offsets_deserialization_start = Instant::now();
            let tainted_offsets_str =
                fs::read_to_string(tainted_offsets_path).context(ReadOffsetsFileFailed)?;
            let mut tainted_offsets: Vec<usize> =
                serde_json::from_str(&tainted_offsets_str).context(ParseOffsetsFileFailed)?;
            ensure!(!tainted_offsets.is_empty(), NoOffsetsProvided);
            tainted_offsets.sort_unstable();
            log::debug!(
                "Tainted offsets deserialization took: {:?}",
                tainted_offsets_deserialization_start.elapsed()
            );

            log::info!("Tainted offsets: {:?}", tainted_offsets);
            TaintInfo::TaintedOffsets(tainted_offsets)
        } else {
            // The tainter is disabled, so initialize the tainted offsets as
            // empty, they will not be used.
            TaintInfo::TaintedOffsets(Vec::new())
        };

        let tainter = Tainter {
            canonical_path_opt,
            taint_info,
            ..Default::default()
        };

        ensure!(TAINTER.set(Mutex::new(tainter)).is_ok(), AlreadyExists);

        Ok(())
    }
}

enum TaintInfo {
    AllTainted,
    TaintedOffsets(Vec<usize>),
}

impl Default for TaintInfo {
    fn default() -> Self {
        Self::AllTainted
    }
}

#[derive(Debug, Snafu)]
pub enum TainterError {
    #[snafu(display("Tainted offsets file path was not provided"))]
    MissingTaintedOffsetsPath,
    #[snafu(display("Cannot read tainted offsets file: {}", source))]
    ReadOffsetsFileFailed { source: std::io::Error },
    #[snafu(display("Cannot parse tainted offsets file: {}", source))]
    ParseOffsetsFileFailed { source: serde_json::Error },
    #[snafu(display("No tainted offsets were provided"))]
    NoOffsetsProvided,
    #[snafu(display("Cannot canonicalize tainted file path {}: {}", path.display(), source))]
    InvalidTaintPath {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Tainter has already been instantiated"))]
    AlreadyExists,
}
