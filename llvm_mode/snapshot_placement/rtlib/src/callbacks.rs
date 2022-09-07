use crate::{
    dfsan::dfsan_label,
    tracer::Tracer,
    xray::{self, XRayEntryType, XRayPatchingStatus},
    FAILURE_EXIT_CODE, SUCCESS_EXIT_CODE,
};

/// Function to call when the first tainted load is performed
pub fn trigger_tracer() {
    log::info!("Tracer triggered");

    let tracer = if let Some(tracer) = Tracer::global() {
        tracer
    } else {
        log::warn!("Tracer not initialized");
        return;
    };

    // Unpatch callbacks when taking the snapshot to avoid spurious callbacks
    let patch_status = unsafe { xray::__xray_unpatch() };
    if patch_status != XRayPatchingStatus::SUCCESS {
        log::error!("Could not patch functions with XRay");
        std::process::exit(FAILURE_EXIT_CODE);
    }

    // In any case, kill the process as soon as the first tainted load is encountered
    match tracer.place_snapshot() {
        Ok(_) => std::process::exit(SUCCESS_EXIT_CODE),
        Err(error) => {
            println!("Error while trying to find target function: {}", error);
            std::process::exit(FAILURE_EXIT_CODE);
        },
    }
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

pub type FunctionID = i32;

pub extern "C" fn xray_custom_handler(function_id: FunctionID, entry_type: XRayEntryType) {
    // Consider TAIL the same as EXIT, the difference does not matter and
    // creates problems with the Angora instrumentation.
    let entry_type = if entry_type == XRayEntryType::TAIL {
        XRayEntryType::EXIT
    } else {
        entry_type
    };

    log::trace!("XRay handler called: {:?} {:?}", function_id, entry_type);

    let mut tracer = if let Some(tracer) = Tracer::global() {
        tracer
    } else {
        log::warn!("Tracer not initialized");
        return;
    };

    if let Err(error) = tracer.record_xray_hook(function_id, entry_type) {
        log::error!("Error while recording XRay hook: {}", error);
        std::process::exit(FAILURE_EXIT_CODE);
    }
}
