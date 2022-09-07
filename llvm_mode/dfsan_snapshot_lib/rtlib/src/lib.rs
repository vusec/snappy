#![feature(c_variadic)]
#![allow(non_snake_case)] // crate name is not snake case

mod callbacks;
mod dfsan;
mod fuzzer;
mod heap_tracer;
mod libc_wrappers;
mod snapshot_target_tracer;
mod stack_map_cache;
mod symbols_cache;
mod tainter;
mod tracer;
mod xray;

use ctor::{ctor, dtor};
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use stack_map_cache::StackMapCache;
use std::{
    env,
    path::{Path, PathBuf},
    process,
    time::Instant,
};
use symbols_cache::SymbolsCache;
use tainter::TainterBuilder;
use tracer::{Tracer, TracerBuilder};

/// Exit code for when the instrumentation run correctly
const SUCCESS_EXIT_CODE: i32 = 42;

/// Exit code for when the instrumentation failed
const FAILURE_EXIT_CODE: i32 = 24;

const ENABLED_VARNAME: &str = "TRACER_ENABLED";
const OUTPUT_FILE_VARNAME: &str = "TRACER_OUTPUT_FILE";
const INPUT_PATH_VARNAME: &str = "TRACER_INPUT_FILE";
const TAINTED_OFFSETS_FILE_VARNAME: &str = "TRACER_TAINTED_OFFSETS_FILE";
const ALL_TAINTED_VARNAME: &str = "TRACER_ALL_TAINTED";
const SNAPSHOT_TARGET_VARNAME: &str = "TRACER_SNAPSHOT_TARGET";

type FunctionID = i32;

fn initialize_xray() {
    let tracer = Tracer::global().unwrap();

    let xray_initialization_start = Instant::now();

    unsafe {
        xray::__xray_init();

        if xray::__xray_set_handler(Some(callbacks::xray_custom_handler)) == 0 {
            log::error!("Could not set custom handler");
            process::exit(FAILURE_EXIT_CODE);
        }

        tracer.patch_target_functions().unwrap_or_else(|e| {
            log::error!("Could not patch target backtrace: {}", e);
            process::exit(FAILURE_EXIT_CODE);
        });
    }

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

fn initialize_tracer(stack_maps_cache: StackMapCache, symbols_cache: SymbolsCache) {
    let mut builder = TracerBuilder::new();

    if let Ok(output_path_string) = env::var(OUTPUT_FILE_VARNAME) {
        builder.output_file(PathBuf::from(output_path_string));
    }

    if let Ok(snapshot_target_path_string) = env::var(SNAPSHOT_TARGET_VARNAME) {
        builder.snapshot_target_path(PathBuf::from(snapshot_target_path_string));
    }

    builder.stack_maps_cache(stack_maps_cache);
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

fn prefill_caches(stack_maps_cache: &mut StackMapCache, symbols_cache: &mut SymbolsCache) {
    let begin = Instant::now();

    TargetSharedLibrary::each(|shlib| {
        let object_path: PathBuf = shlib.name().into();

        // Skip VDSO because it is not present on disk, skip empty string found in some binaries.
        if object_path == Path::new("linux-vdso.so.1") || object_path == Path::new("") {
            return;
        }

        if let Err(error) = stack_maps_cache.get_stack_map(&object_path) {
            if !matches!(
                error,
                stack_map_cache::Error::StackMapsSectionNotFound { path: _ }
            ) {
                log::error!("Error prefilling stack maps cache: {}", error);
                std::process::exit(FAILURE_EXIT_CODE);
            }
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
    heap_tracer::with_tracer_disabled(|| {
        env_logger::init();

        if env::var(ENABLED_VARNAME).is_err() {
            log::info!("Instrumentation disabled");
            return;
        }

        let mut stack_maps_cache = StackMapCache::default();
        let mut symbols_cache = SymbolsCache::default();
        prefill_caches(&mut stack_maps_cache, &mut symbols_cache);

        let fuzzer = fuzzer::build_fuzzer();
        if let Err(error) = fuzzer.snapshot(true) {
            log::error!("Could not create snapshot in ctor: {}", error);
            process::exit(FAILURE_EXIT_CODE);
        }

        let initialization_start = Instant::now();

        initialize_tainter();
        initialize_tracer(stack_maps_cache, symbols_cache);
        initialize_xray();

        log::info!("Initialization took: {:?}", initialization_start.elapsed());
    })
}

#[dtor]
fn dfsan_snapshot_destructor() {
    heap_tracer::with_tracer_disabled(|| {
        if let Some(tracer) = Tracer::global() {
            if let Err(error) = unsafe { tracer.unpatch_target_functions() } {
                log::warn!("Error while unpatching functions: {}", error);
            }
        } else {
            log::debug!("Tracer not initialized, skipping destructor");
        }
    })
}
