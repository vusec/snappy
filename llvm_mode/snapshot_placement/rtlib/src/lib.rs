#![feature(c_variadic)]
#![allow(non_snake_case)] // crate name is not snake case

mod callbacks;
mod dfsan;
mod fuzzer;
mod libc_wrappers;
mod symbols_cache;
mod tainter;
mod tracer;
mod xray;

use ctor::ctor;
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use std::{
    env,
    path::{Path, PathBuf},
    process,
    time::Instant,
};
use symbols_cache::SymbolsCache;
use tainter::TainterBuilder;
use tracer::TracerBuilder;
use xray::XRayPatchingStatus;

/// Exit code for when the instrumentation run correctly
const SUCCESS_EXIT_CODE: i32 = 42;

/// Exit code for when the instrumentation failed
const FAILURE_EXIT_CODE: i32 = 24;

const ENABLED_VARNAME: &str = "TRACER_ENABLED";
const OUTPUT_FILE_VARNAME: &str = "TRACER_OUTPUT_FILE";
const INPUT_PATH_VARNAME: &str = "TRACER_INPUT_FILE";
const TAINTED_OFFSETS_FILE_VARNAME: &str = "TRACER_TAINTED_OFFSETS_FILE";
const ALL_TAINTED_VARNAME: &str = "TRACER_ALL_TAINTED";

fn initialize_xray() {
    let xray_initialization_start = Instant::now();

    unsafe {
        xray::__xray_init();

        if xray::__xray_set_handler(Some(callbacks::xray_custom_handler)) == 0 {
            log::error!("Could not set custom handler");
            process::exit(FAILURE_EXIT_CODE);
        }

        let patch_status = xray::__xray_patch();
        if patch_status != XRayPatchingStatus::SUCCESS {
            log::error!("Could not patch functions with XRay");
            process::exit(FAILURE_EXIT_CODE);
        }
    };

    log::debug!(
        "XRay initialization took: {:?}",
        xray_initialization_start.elapsed()
    );
}

fn initialize_tainter() {
    let mut builder = TainterBuilder::new();

    if let Ok(input_path_string) = env::var(INPUT_PATH_VARNAME) {
        builder.taint_file(PathBuf::from(input_path_string));
    }

    if let Ok(tainted_offsets_path_string) = env::var(TAINTED_OFFSETS_FILE_VARNAME) {
        builder.tainted_offsets_file(PathBuf::from(tainted_offsets_path_string));
    }

    if env::var(ALL_TAINTED_VARNAME).is_ok() {
        builder.all_tainted();
    }

    let tainter_building_start = Instant::now();
    builder.build_global().unwrap_or_else(|e| {
        log::error!("Error during tainter initialization: {}", e);
        process::exit(FAILURE_EXIT_CODE);
    });
    log::debug!(
        "Building tainter took: {:?}",
        tainter_building_start.elapsed()
    );
}

fn initialize_tracer(symbols_cache: SymbolsCache) {
    let mut builder = TracerBuilder::new();

    if let Ok(output_path_string) = env::var(OUTPUT_FILE_VARNAME) {
        builder.output_file(PathBuf::from(output_path_string));
    }

    builder.symbols_cache(symbols_cache);

    let tracer_building_start = Instant::now();
    builder.build_global().unwrap_or_else(|e| {
        log::error!("Error during tainter initialization: {}", e);
        process::exit(FAILURE_EXIT_CODE);
    });
    log::debug!(
        "Building tracer took: {:?}",
        tracer_building_start.elapsed()
    );
}

fn prefill_symbols_cache(symbols_cache: &mut SymbolsCache) {
    let begin = Instant::now();

    TargetSharedLibrary::each(|shlib| {
        let object_path: PathBuf = shlib.name().into();

        // Skip VDSO because it is not present on disk, skip empty string found in some binaries.
        if object_path == Path::new("linux-vdso.so.1") || object_path == Path::new("") {
            return;
        }

        symbols_cache
            .get_symbols_for_binary(&object_path)
            .unwrap_or_else(|error| {
                log::error!("Error prefilling reversed symbols cache: {}", error);
                std::process::exit(FAILURE_EXIT_CODE);
            });
    });

    log::debug!("Precaching took: {:?}", begin.elapsed());
}

#[ctor]
fn dfsan_snapshot_constructor() {
    env_logger::init();

    if env::var(ENABLED_VARNAME).is_err() {
        log::info!("Instrumentation disabled");
        return;
    }

    let mut symbols_cache = SymbolsCache::default();
    prefill_symbols_cache(&mut symbols_cache);

    let fuzzer = fuzzer::build_fuzzer();
    if let Err(error) = fuzzer.snapshot(true) {
        log::error!("Could not create snapshot in ctor: {}", error);
        process::exit(FAILURE_EXIT_CODE);
    }

    let initialization_start = Instant::now();

    initialize_xray();
    initialize_tainter();
    initialize_tracer(symbols_cache);

    log::info!("Initialization took: {:?}", initialization_start.elapsed());
}
