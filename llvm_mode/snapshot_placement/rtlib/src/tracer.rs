use crate::{
    callbacks::FunctionID,
    symbols_cache::{self, SymbolsCache},
    xray::{XRayEntryType, __xray_function_address},
};
use backtrace::Backtrace;
use libc::c_void;
use log::log_enabled;
use once_cell::sync::OnceCell;
use procfs::process::{MMapPath, MemoryMap, Process};
use serde::Serialize;
use snafu::{ensure, OptionExt, ResultExt, Snafu};
use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

static TRACER: OnceCell<Mutex<Tracer>> = OnceCell::new();

#[derive(Default)]
pub struct Tracer {
    output_path_opt: Option<PathBuf>,
    symbols_to_counts: HashMap<(String, XRayEntryType), usize>,
    last_entry_recorded: Option<(String, XRayEntryType)>,

    symbols_cache: SymbolsCache,
    memory_maps: Vec<MemoryMap>,
}

impl Tracer {
    pub fn global() -> Option<MutexGuard<'static, Self>> {
        let lock = TRACER.get()?;
        Some(lock.lock().unwrap())
    }

    fn log_backtrace(&self, backtrace: &Backtrace) {
        let backtrace_str = format!("{:?}", backtrace);
        for line in backtrace_str.lines() {
            log::trace!("{}", line);
        }
    }

    fn get_target_hook_info(&self) -> Result<TargetHookInfo, TracerError> {
        let target_hook = self
            .last_entry_recorded
            .as_ref()
            .expect("Snapshotting without encountering hooks");
        let target_hook_count = self.symbols_to_counts[target_hook];

        Ok(TargetHookInfo {
            symbol_name: target_hook.0.to_string(),
            symbol_type: format!("{:?}", target_hook.1),
            hit_count: target_hook_count,
        })
    }

    pub fn place_snapshot(&self) -> Result<(), TracerError> {
        let place_snapshot_start = Instant::now();

        let output_path = if let Some(output_path) = self.output_path_opt.as_ref() {
            output_path
        } else {
            log::debug!("Instrumentation disabled");
            return Ok(());
        };

        if log_enabled!(log::Level::Trace) {
            log::trace!("Placing snapshot at:");
            let backtrace = Backtrace::new();
            self.log_backtrace(&backtrace);
        }

        let target_hook_info = self.get_target_hook_info()?;

        log::info!("Writing backtrace symbols to file");
        let mut output_file = BufWriter::new(File::create(output_path).context(OpenOutputError)?);
        serde_json::to_writer_pretty(output_file.by_ref(), &target_hook_info)
            .context(OutputWriteError)?;
        output_file.flush().context(FileFlushError)?;

        log::info!(
            "Placing snapshot took: {:?}",
            place_snapshot_start.elapsed()
        );

        Ok(())
    }

    fn find_symbol_for_address(&mut self, target_address: CodePtr) -> Result<String, TracerError> {
        log::trace!("Resolving address: {:?}", target_address);

        let target_map = self
            .memory_maps
            .iter()
            .find(|map| {
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

        let binary_path = if let MMapPath::Path(binary_path) = &target_map.pathname {
            binary_path
        } else {
            return NotFileAddress {
                address: target_address,
            }
            .fail();
        };

        let symbols_map = self
            .symbols_cache
            .get_symbols_for_binary(&binary_path)
            .context(SymbolsCacheError)?;
        match symbols_map.get_key_value(&target_address) {
            Some((range, symbol)) => {
                log::trace!(
                    "Matched symbol: ({:?},{:?}):{} {}",
                    range.start,
                    range.end,
                    range.end.offset_from(range.start),
                    symbol,
                );
                Ok(symbol.clone())
            },
            None => NoSymbolFound {
                address: target_address,
            }
            .fail(),
        }
    }

    pub fn record_xray_hook(
        &mut self,
        function_id: FunctionID,
        entry_type: XRayEntryType,
    ) -> Result<(), TracerError> {
        let xray_hook_start = Instant::now();

        let function_address = unsafe { __xray_function_address(function_id) as *mut c_void };

        let symbol_name = self.find_symbol_for_address(CodePtr::from(function_address))?;

        let hook_counter = self
            .symbols_to_counts
            .entry((symbol_name.clone(), entry_type))
            .or_insert(0);
        *hook_counter += 1;

        log::trace!(
            "XRay hook recording for '{}' took: {:?}",
            symbol_name,
            xray_hook_start.elapsed()
        );

        self.last_entry_recorded = Some((symbol_name, entry_type));

        Ok(())
    }
}

#[derive(Serialize)]
struct TargetHookInfo {
    symbol_name: String,
    symbol_type: String,
    hit_count: usize,
}

// This type represents a pointer that cannot be dereferenced, it is used
// only to represent address ranges
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodePtr(*const u8);

impl CodePtr {
    pub fn offset_from(self, other: CodePtr) -> isize {
        unsafe { self.0.offset_from(other.0) }
    }

    pub fn offset(self, count: isize) -> CodePtr {
        unsafe { CodePtr::from(self.0.offset(count)) }
    }

    pub fn add(self, count: usize) -> CodePtr {
        unsafe { CodePtr::from(self.0.add(count)) }
    }

    pub fn sub(self, count: usize) -> CodePtr {
        unsafe { CodePtr::from(self.0.sub(count)) }
    }
}

unsafe impl Send for CodePtr {}

impl<T> From<*const T> for CodePtr {
    fn from(ptr: *const T) -> Self {
        Self(ptr as *const u8)
    }
}

impl<T> From<*mut T> for CodePtr {
    fn from(ptr: *mut T) -> Self {
        Self(ptr as *const u8)
    }
}

impl From<CodePtr> for *const u8 {
    fn from(ptr: CodePtr) -> Self {
        ptr.0
    }
}

impl Debug for CodePtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Default)]
pub struct TracerBuilder {
    output_path_opt: Option<PathBuf>,
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

    pub fn symbols_cache(&mut self, symbols_cache: SymbolsCache) -> &mut Self {
        self.symbols_cache = Some(symbols_cache);
        self
    }

    pub fn build_global(self) -> Result<(), TracerError> {
        let process = Process::myself().context(ProcfsError)?;
        let memory_maps = process.maps().context(ProcfsError)?;

        let tracer = if let Some(output_path) = self.output_path_opt {
            Tracer {
                output_path_opt: Some(output_path),
                symbols_cache: self.symbols_cache.unwrap_or_default(),
                memory_maps,
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

#[derive(Debug, Snafu)]
pub enum TracerError {
    #[snafu(display("Could not retrieve data from procfs: {}", source))]
    ProcfsError {
        source: procfs::ProcError,
    },
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
    #[snafu(display("Could not associate map to address: {:?}", address))]
    MapNotFound {
        address: CodePtr,
    },
    NotFileAddress {
        address: CodePtr,
    },
    SymbolsCacheError {
        source: symbols_cache::Error,
    },
    NoSymbolFound {
        address: CodePtr,
    },
}
