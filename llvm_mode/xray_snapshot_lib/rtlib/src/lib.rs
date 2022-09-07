#![allow(non_snake_case)] // crate name is not snake case
#![feature(allocator_api)]

mod xray;
use resolver::ResolverBuilder;
use xray::XRayEntryType;

mod controller;
use controller::{Controller, ControllerBuilder};

mod snapshot_target_tracer;
use snapshot_target_tracer::SnapshotTargetTracer;

mod fuzzer;
mod heap_tracer;
mod resolver;
mod stack_map_cache;
mod symbols_cache;

use ctor::{ctor, dtor};
use std::{env, path::PathBuf, process};

const TAINTS_VARNAME: &str = "XRAY_SNAPSHOT_TAINTS";
const ENABLED_VARNAME: &str = "TRACER_ENABLED";
const OUTPUT_FILE_VARNAME: &str = "TRACER_OUTPUT_FILE";
const MACHINE_READABLE_VARNAME: &str = "TRACER_MACHINE_READABLE";
const SNAPSHOT_TARGET_VARNAME: &str = "TRACER_SNAPSHOT_TARGET";
const STATS_ONLY_VARNAME: &str = "TRACER_STATS_ONLY";

type FunctionID = i32;

/// Exit code for when the instrumentation failed
pub const FAILURE_EXIT_CODE: i32 = 24;

extern "C" fn xray_custom_handler(function_id: FunctionID, entry_kind: XRayEntryType) {
    heap_tracer::with_tracer_disabled(|| {
        log::trace!("Custom handler called: {:?} {:?}", function_id, entry_kind);

        // Angora context instrumentation breaks all tail calls, so merge TAIL
        // into EXIT. It does not make any difference for this instrumentation.
        let entry_kind = if entry_kind != XRayEntryType::TAIL {
            entry_kind
        } else {
            XRayEntryType::EXIT
        };

        if let Err(error) = SnapshotTargetTracer::record_xray_hook(function_id, entry_kind) {
            log::error!("Error while recording XRay hook: {}", error);
            std::process::exit(FAILURE_EXIT_CODE);
        }
    })
}

fn initialize_controller(mut resolver_builder: ResolverBuilder) {
    let taints_path: PathBuf = env::var_os(TAINTS_VARNAME)
        .unwrap_or_else(|| {
            log::error!("Taints file missing, set var: {}", TAINTS_VARNAME);
            process::exit(FAILURE_EXIT_CODE);
        })
        .into();
    resolver_builder.taints_path(taints_path);

    let mut builder = ControllerBuilder::new();

    if let Ok(output_path_string) = env::var(OUTPUT_FILE_VARNAME) {
        builder.output_file(PathBuf::from(output_path_string));
    }

    if env::var(MACHINE_READABLE_VARNAME).is_ok() {
        builder.machine_readable_output();
    }

    if let Ok(snapshot_target_path_string) = env::var(SNAPSHOT_TARGET_VARNAME) {
        builder.snapshot_target_path(PathBuf::from(snapshot_target_path_string));
    }

    if env::var(STATS_ONLY_VARNAME).is_ok() {
        builder.stats_only();
    }

    builder.resolver(resolver_builder.build());

    builder.build_global().unwrap_or_else(|e| {
        log::error!("Error during controller initialization: {}", e);
        process::exit(FAILURE_EXIT_CODE);
    });
}

#[ctor]
fn xray_snapshot_constructor() {
    heap_tracer::with_tracer_disabled(|| {
        env_logger::init();

        if env::var(ENABLED_VARNAME).is_err() {
            log::debug!("Tracer not enabled");
            return;
        }

        let mut resolver_builder = ResolverBuilder::new();
        if let Err(error) = resolver_builder.prefill_caches() {
            log::error!("Could not prefill caches: {}", error);
            process::exit(FAILURE_EXIT_CODE);
        }

        // This fork server produces other fork servers, so the parent process
        // should not wait for its children.
        let fuzzer = fuzzer::build_fuzzer();
        if let Err(error) = fuzzer.snapshot(false) {
            if matches!(error, fuzzer::Error::ForkServerShouldExit) {
                process::exit(0);
            } else {
                log::error!("Could not create snapshot in ctor: {}", error);
                process::exit(FAILURE_EXIT_CODE);
            }
        }

        initialize_controller(resolver_builder);

        let mut controller = Controller::global().unwrap();

        unsafe {
            xray::__xray_init();

            if xray::__xray_set_handler(Some(xray_custom_handler)) == 0 {
                log::error!("Could not set custom handler");
                process::exit(FAILURE_EXIT_CODE);
            }

            controller.patch_target_functions().unwrap_or_else(|e| {
                log::error!("Could not patch target backtrace: {}", e);
                process::exit(FAILURE_EXIT_CODE);
            })
        };

        controller.trace_execution_start();
    })
}

#[dtor]
fn xray_snapshot_destructor() {
    heap_tracer::with_tracer_disabled(|| {
        if let Some(mut controller) = Controller::global() {
            controller.trace_execution_end();
            if controller.stats_only() {
                controller.write_data().unwrap_or_else(|e| {
                    log::error!("Could not write to output file: {}", e);
                    process::exit(FAILURE_EXIT_CODE);
                });
            }
        } else {
            log::debug!("Tracer not initialized, skipping destructor");
        }
    })
}
