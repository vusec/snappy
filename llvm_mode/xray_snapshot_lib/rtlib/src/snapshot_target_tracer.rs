use super::FunctionID;
use crate::{
    controller::{self, Controller, SnapshotTarget},
    fuzzer,
    xray::XRayEntryType,
};
use snafu::Snafu;
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
            let controller = Controller::global().expect("Controller not initialized yet");
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
    ) -> Result<bool, SnapshotTargetTracerError> {
        Self::lazy_init();

        THREAD_TRACER.with(|thread_tracer| {
            let mut thread_tracer_opt = thread_tracer.borrow_mut();
            let thread_tracer = thread_tracer_opt
                .as_mut()
                .expect("Matched TargetTracer was reused");

            if !thread_tracer
                .snapshot_target
                .target_ids()
                .contains(&function_id)
            {
                return MismatchedHook.fail();
            }

            if entry_kind != thread_tracer.snapshot_target.target_kind() {
                // Both ENTRY and EXIT are reported, but only one triggers
                // the snapshot.
                return Ok(false);
            }

            thread_tracer.current_hit_count += 1;

            if thread_tracer.current_hit_count == thread_tracer.snapshot_target.hit_count() {
                log::info!("Target hit count matched");

                // Destroy this tracer before taking the snapshot, so it will
                // not be destroyed on exit. This function will not be entered
                // anymore because the XRay callbacks are disabled before taking
                // the snapshot.
                *thread_tracer_opt = None;

                let snapshot_result;
                {
                    let mut controller = Controller::global().expect("Tracer not initialized yet");
                    snapshot_result = controller.trigger_snapshot();
                }

                if let Err(error) = snapshot_result {
                    match error {
                        controller::Error::SnapshotFailed {
                            source: fuzzer::Error::ForkServerShouldExit,
                        } => {
                            // Exit after releasing the lock on the controller.
                            std::process::exit(0);
                        }
                        error => {
                            return Err(SnapshotTargetTracerError::SnapshotFailed { source: error })
                        }
                    }
                }

                Ok(true)
            } else {
                Ok(false)
            }
        })
    }
}

#[derive(Debug, Snafu)]
pub enum SnapshotTargetTracerError {
    #[snafu(display("Snapshotting failed: {}", source))]
    SnapshotFailed { source: controller::Error },
    #[snafu(display("SnapshotTargetTracer not initialized yet"))]
    UninitializedTracer,
    #[snafu(display("Report from non-target function"))]
    MismatchedHook,
}
