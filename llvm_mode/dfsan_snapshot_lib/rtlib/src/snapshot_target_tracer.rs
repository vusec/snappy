use super::FunctionID;
use crate::{
    heap_tracer,
    tracer::{SnapshotTarget, Tracer, TracerError},
    xray::XRayEntryType,
};
use snafu::{ResultExt, Snafu};
use std::{cell::RefCell, thread};

thread_local!(static THREAD_TRACER: RefCell<Option<SnapshotTargetTracer>> = RefCell::new(None));

/// This structure is a thread-local singleton. It keeps track of how many times
/// the functions in the snapshot target have been encountered. When the target
/// hit count is matched, the snapshotting system is triggered.
pub struct SnapshotTargetTracer {
    snapshot_target: SnapshotTarget,
    current_hit_count: usize,
}

impl SnapshotTargetTracer {
    fn lazy_init() -> bool {
        THREAD_TRACER.with(|thread_tracer| {
            if thread_tracer.borrow().is_some() {
                // Already initialized
                return false;
            }

            log::debug!(
                "Initializing snapshot target tracer for thread: {:?}",
                thread::current().id()
            );

            // Clone the snapshot target from the controller. If each thread has
            // its own copy of the target trace, there is no need for locking on
            // every instrumented function call.
            let controller = Tracer::global().expect("Controller not initialized yet");
            let mut thread_tracer = thread_tracer.borrow_mut();

            let snapshot_target = controller.snapshot_target().clone();

            *thread_tracer = Some(Self {
                snapshot_target,
                current_hit_count: 0,
            });

            // Initialization performed
            true
        })
    }

    pub fn record_xray_hook(
        function_id: FunctionID,
        entry_kind: XRayEntryType,
    ) -> Result<bool, StackTracerError> {
        heap_tracer::with_tracer_disabled(|| {
            Self::lazy_init();

            THREAD_TRACER.with(|thread_tracer| {
                let mut thread_tracer = thread_tracer.borrow_mut();
                let thread_tracer = thread_tracer.as_mut().unwrap();

                if !thread_tracer
                    .snapshot_target
                    .target_ids()
                    .contains(&function_id)
                {
                    return MismatchedHook { function_id }.fail();
                }

                if entry_kind != thread_tracer.snapshot_target.target_kind() {
                    // Both ENTRY and EXIT are reported, but only one triggers
                    // the snapshot.
                    return Ok(false);
                }

                thread_tracer.current_hit_count += 1;

                if thread_tracer.current_hit_count == thread_tracer.snapshot_target.hit_count() {
                    log::info!("Target hit count matched");

                    let mut controller = Tracer::global().expect("Tracer not initialized yet");
                    controller.record_snapshot().context(SnapshotFailed)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            })
        })
    }
}

#[derive(Debug, Snafu)]
pub enum StackTracerError {
    #[snafu(display("Snapshotting failed: {}", source))]
    SnapshotFailed { source: TracerError },
    #[snafu(display("SnapshotTargetTracer not initialized yet"))]
    UninitializedTracer,
    #[snafu(display("Report from non-target function: {}", function_id))]
    MismatchedHook { function_id: FunctionID },
}
