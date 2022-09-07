use super::{FunctionID, FAILURE_EXIT_CODE, SUCCESS_EXIT_CODE};
use crate::{
    dfsan::dfsan_label, heap_tracer, snapshot_target_tracer::SnapshotTargetTracer, tracer::Tracer,
    xray::XRayEntryType,
};

/// Function to call when the first tainted load is performed
pub fn trigger_tracer() {
    // Calling `exit` triggers deallocations
    heap_tracer::with_tracer_disabled(|| {
        log::info!("Tracer triggered");

        let mut tracer = if let Some(tracer) = Tracer::global() {
            tracer
        } else {
            log::warn!("Tracer not initialized");
            return;
        };

        // In any case, kill the process as soon as the first tainted load is encountered
        match tracer.report_tainted_load() {
            Ok(_) => std::process::exit(SUCCESS_EXIT_CODE),
            Err(error) => {
                println!("Error while trying to find target function: {}", error);
                std::process::exit(FAILURE_EXIT_CODE);
            },
        }
    });
}

/// Event callback triggered on every load from memory performed by the program
#[no_mangle]
pub unsafe extern "C" fn __dfsan_load_callback(label: dfsan_label) {
    if label == 0 {
        // Return if no tainted byte was loaded
        return;
    }

    trigger_tracer();
}

#[no_mangle]
pub unsafe extern "C" fn __dfsan_store_callback(_label: dfsan_label) {}

#[no_mangle]
pub unsafe extern "C" fn __dfsan_mem_transfer_callback(_start: *mut dfsan_label, _len: usize) {}

#[no_mangle]
pub unsafe extern "C" fn __dfsan_cmp_callback(_combined_label: dfsan_label) {}

pub extern "C" fn xray_custom_handler(function_id: FunctionID, entry_type: XRayEntryType) {
    heap_tracer::with_tracer_disabled(|| {
        let entry_type = if entry_type == XRayEntryType::TAIL {
            XRayEntryType::EXIT
        } else {
            entry_type
        };

        log::trace!("XRay handler called: {:?} {:?}", function_id, entry_type);

        match SnapshotTargetTracer::record_xray_hook(function_id, entry_type) {
            Ok(snapshot_performed) => {
                if snapshot_performed {
                    std::process::exit(SUCCESS_EXIT_CODE);
                }
            },
            Err(error) => {
                log::error!("Error while recording XRay hook: {}", error);
                std::process::exit(FAILURE_EXIT_CODE);
            },
        };
    })
}
