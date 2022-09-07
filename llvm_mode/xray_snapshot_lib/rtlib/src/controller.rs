use super::FunctionID;
use crate::{
    fuzzer::{self, Fuzzer},
    heap_tracer::{self},
    resolver::{self, DataPtr, Resolver},
    xray::{self, XRayEntryType, XRayPatchingStatus},
};
use log::log_enabled;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use std::{
    fmt,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

static TRACER: OnceCell<Mutex<Controller>> = OnceCell::new();

pub struct Controller {
    output_path: Option<PathBuf>,
    machine_readable_output: bool,
    stats_only: bool,

    snapshot_target: Option<SnapshotTarget>,

    execution_start: Option<Instant>,
    snapshot_time: Option<Instant>,
    resume_time: Option<Instant>,
    execution_end: Option<Instant>,

    resolver: Option<Resolver>,
    fuzzer: Box<dyn Fuzzer + Send>,
}

impl Controller {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        let lock = TRACER.get()?;
        Some(lock.lock().unwrap())
    }

    pub fn trace_execution_start(&mut self) {
        // This function should always be called when the program is started
        assert!(self.execution_start.is_none());
        assert!(self.snapshot_time.is_none());
        assert!(self.execution_end.is_none());
        self.execution_start = Some(Instant::now());

        log::trace!("Start time recorded: {:?}", self.execution_start.unwrap());
    }

    pub fn trace_execution_end(&mut self) {
        // This function should always be called when the program is terminated
        assert!(self.execution_start.is_some());
        assert!(self.execution_end.is_none());
        self.execution_end = Some(Instant::now());

        log::trace!("End time recorded: {:?}", self.execution_end.unwrap());

        if let Some(resume_time) = self.resume_time {
            let execution_end = self.execution_end.unwrap();
            log::info!(
                "Execution time after resume: {:?}",
                execution_end.duration_since(resume_time)
            );
        }
    }

    fn trace_snapshot_time(&mut self) -> Result<(), Error> {
        if self.snapshot_time.is_some() {
            return AlreadySnapshotted.fail();
        }

        self.snapshot_time = Some(Instant::now());
        log::trace!("Snapshot recorded: {:?}", self.snapshot_time.unwrap());

        Ok(())
    }

    fn trace_resume_time(&mut self) {
        assert!(self.snapshot_time.is_some());
        assert!(self.resume_time.is_none());

        self.resume_time = Some(Instant::now());
        log::trace!("Execution resumed: {:?}", self.resume_time.unwrap());
    }

    pub fn trace_alloc(&mut self, ptr: DataPtr, size: usize) {
        heap_tracer::with_tracer_disabled(|| {
            if let Some(resolver) = self.resolver.as_mut() {
                log::trace!("Heap allocation: {:?} ({} bytes)", ptr, size);
                resolver.trace_alloc(ptr, size);
            }
        })
    }

    pub fn trace_dealloc(&mut self, ptr: DataPtr) {
        heap_tracer::with_tracer_disabled(|| {
            if let Some(resolver) = self.resolver.as_mut() {
                log::trace!("Heap deallocation: {:?}", ptr);
                resolver.trace_dealloc(ptr);
            }
        })
    }

    pub unsafe fn patch_target_functions(&self) -> Result<(), Error> {
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

    pub unsafe fn unpatch_target_functions(&self) -> Result<(), Error> {
        for target_id in self.snapshot_target.as_ref().unwrap().target_ids() {
            let patch_status = xray::__xray_unpatch_function(*target_id);
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

    pub fn snapshot_target(&self) -> &SnapshotTarget {
        self.snapshot_target.as_ref().unwrap()
    }

    fn log_mapped_memory() {
        let me = procfs::process::Process::myself().unwrap();

        log::debug!("process rss: {} pages", me.stat().unwrap().rss);

        let mut total_rss = 0;
        log::debug!("maps:");
        for (map, map_data) in me.smaps().unwrap() {
            if let Some(rss) = map_data.map.get("Rss") {
                total_rss += rss;
                log::debug!(
                    "  rss: {} pages,\tperms: {}, addr: ({:#14x},{:#14x})\tpath: {:?}",
                    rss / 4096,
                    map.perms,
                    map.address.0,
                    map.address.1,
                    map.pathname
                );
            }
        }
        log::debug!("total rss: {} pages", total_rss / 4096);
    }

    pub fn trigger_snapshot(&mut self) -> Result<(), Error> {
        unsafe {
            log::info!("Unpatching functions in backtrace");
            self.unpatch_target_functions()?;
        }

        self.trace_snapshot_time()?;
        if self.stats_only {
            return Ok(());
        }

        let taints = {
            let mut resolver = self.resolver.take().unwrap();
            resolver.disable_heap_tracing();

            if log_enabled!(log::Level::Debug) {
                resolver.log_allocator_info();
            }

            resolver.resolve_taints()?
        };

        if log::log_enabled!(log::Level::Debug) {
            Self::log_mapped_memory();
        }

        log::info!("Triggering snapshot");
        self.fuzzer.snapshot(true).context(SnapshotFailed)?;

        for (target_ptr, offset) in taints {
            // You can only hope that the resolution was completed correctly
            unsafe {
                *target_ptr = self
                    .fuzzer
                    .get_byte_at_offset(offset)
                    .context(TaintedOffsetOutOfBounds)?
            };
        }

        self.trace_resume_time();

        Ok(())
    }

    pub fn write_data(&self) -> Result<(), Error> {
        assert!(self.stats_only);

        log::info!("Writing results to file");

        let execution_start = self.execution_start.unwrap();
        let execution_end = self.execution_end.unwrap();
        let execution_duration = execution_end.duration_since(execution_start);

        let target_function_entry_to_end_opt =
            self.snapshot_time.map(|target_function_entry_time| {
                execution_end.duration_since(target_function_entry_time)
            });

        let analysis_result = AnalysisResult {
            execution_nanos: execution_duration.as_nanos(),
            target_function_entry_to_end_nanos_opt: target_function_entry_to_end_opt
                .map(|duration| duration.as_nanos()),
        };

        let output_file_exists = self.output_path.as_ref().unwrap().exists();

        let output_file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(self.output_path.as_ref().unwrap())
            .context(OpenOutputError)?;

        let mut output_writer = BufWriter::new(output_file);

        if !self.machine_readable_output {
            write!(output_writer, "{}", analysis_result).context(WriteOutputError)
        } else {
            let mut csv_writer = csv::WriterBuilder::new()
                .has_headers(!output_file_exists)
                .from_writer(output_writer);
            csv_writer
                .serialize(analysis_result)
                .context(SerializeOutputError)
        }
    }

    pub fn stats_only(&self) -> bool {
        self.stats_only
    }
}

#[derive(Default)]
pub struct ControllerBuilder {
    output_path: Option<PathBuf>,
    machine_readable_output: bool,
    snapshot_target_path: Option<PathBuf>,
    stats_only: bool,
    resolver: Option<Resolver>,
}

impl ControllerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn output_file(&mut self, file_path: PathBuf) -> &mut Self {
        self.output_path = Some(file_path);
        self
    }

    pub fn machine_readable_output(&mut self) -> &mut Self {
        self.machine_readable_output = true;
        self
    }

    pub fn snapshot_target_path(&mut self, snapshot_target_path: PathBuf) -> &mut Self {
        self.snapshot_target_path = Some(snapshot_target_path);
        self
    }

    pub fn stats_only(&mut self) -> &mut Self {
        self.stats_only = true;
        self
    }

    pub fn resolver(&mut self, resolver: Resolver) -> &mut Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn build_global(self) -> Result<(), Error> {
        let snapshot_target_path = self
            .snapshot_target_path
            .context(MissingSnapshotTargetPath)?;

        let snapshot_target_file =
            File::open(snapshot_target_path).context(OpenSnapshotFileFailed)?;
        let snapshot_target_reader = BufReader::new(snapshot_target_file);

        let snapshot_target_dump: SnapshotTargetDump =
            serde_json::from_reader(snapshot_target_reader).context(SnapshotTargetDecodeFailed)?;
        let snapshot_target = snapshot_target_dump.into_snapshot_target()?;

        let resolver = self.resolver.expect("Resolver was not provided");

        let fuzzer = fuzzer::build_fuzzer();

        let tracer = Controller {
            output_path: self.output_path,
            machine_readable_output: self.machine_readable_output,
            snapshot_target: Some(snapshot_target),
            stats_only: self.stats_only,
            fuzzer,
            execution_start: None,
            snapshot_time: None,
            resume_time: None,
            execution_end: None,
            resolver: Some(resolver),
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
    pub fn into_snapshot_target(self) -> Result<SnapshotTarget, Error> {
        let target_kind = match self.target_kind.as_str() {
            "ENTRY" => XRayEntryType::ENTRY,
            "EXIT" => XRayEntryType::EXIT,
            // Angora context breaks all tail calls, merge TAIL into EXIT.
            "TAIL" => XRayEntryType::EXIT,
            kind => {
                return InvalidTargetKind {
                    kind: kind.to_string(),
                }
                .fail()
            }
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

#[derive(Serialize)]
struct AnalysisResult {
    execution_nanos: u128,
    target_function_entry_to_end_nanos_opt: Option<u128>,
}

impl fmt::Display for AnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(target_function_entry_to_end) = self.target_function_entry_to_end_nanos_opt {
            let speedup = self.execution_nanos as f64 / target_function_entry_to_end as f64;

            writeln!(f, "speedup:\t\t\t{:.4}x", speedup)?;
            writeln!(
                f,
                "target function entry to end:\t{:?}",
                target_function_entry_to_end
            )?;
        } else {
            writeln!(f, "target function not hit")?;
        }

        writeln!(f, "total execution time:\t\t{:?}", self.execution_nanos)
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Tainter has already been instantiated"))]
    AlreadyExists,
    #[snafu(display(
        "Could not patch function {}, failed with status: {:?}",
        function_id,
        status
    ))]
    PatchFailed {
        function_id: FunctionID,
        status: XRayPatchingStatus,
    },
    #[snafu(display("The snapshot has already happened"))]
    AlreadySnapshotted,
    #[snafu(display("Could not open output file: {}", source))]
    OpenOutputError {
        source: std::io::Error,
    },
    #[snafu(display("Could not write to output file: {}", source))]
    WriteOutputError {
        source: std::io::Error,
    },
    #[snafu(display("Could not serialize result: {}", source))]
    SerializeOutputError {
        source: csv::Error,
    },
    InvalidTargetKind {
        kind: String,
    },
    MissingSnapshotTargetPath,
    OpenSnapshotFileFailed {
        source: std::io::Error,
    },
    SnapshotTargetDecodeFailed {
        source: serde_json::Error,
    },
    SnapshotFailed {
        source: fuzzer::Error,
    },
    TaintedOffsetOutOfBounds {
        source: fuzzer::Error,
    },
    #[snafu(context(false))]
    ResolverError {
        source: resolver::Error,
    },
}
