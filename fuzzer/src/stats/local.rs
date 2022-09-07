use super::*;
use crate::{
    cond_stmt::CondStmt,
    executor::{StatusType, TargetHookInfo},
    fuzz_type::FuzzType,
};

use hdrhistogram::Histogram;

pub struct LocalStats {
    pub fuzz_type: FuzzType,
    pub current_test_case: u64,
    pub current_snapshot_position: Option<TargetHookInfo>,

    pub num_exec: Counter,
    pub num_snapshots: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,

    pub track_time: TimeDuration,
    pub snapshot_time: TimeDuration,
    pub start_time: TimeIns,

    pub avg_exec_time: SyncAverage,
    pub avg_edge_num: SyncAverage,

    pub hist_execs_per_snap_cond: Histogram<u64>,
    pub hist_execs_per_snapshot: Histogram<u64>,
    pub hist_delayed_execs_micros: Histogram<u64>,
    pub hist_plain_execs_micros: Histogram<u64>,
    pub hist_track_micros: Histogram<u64>,
    pub hist_snapshot_micros: Histogram<u64>,

    pub snapshot_threshold: Option<u64>,
}

impl LocalStats {
    pub fn register(&mut self, cond: &CondStmt) {
        self.fuzz_type = cond.get_fuzz_type();
        self.current_test_case = cond.base.belong as u64;
        self.current_snapshot_position = None;
        self.clear();
    }

    pub fn clear(&mut self) {
        self.num_exec = Default::default();
        self.num_snapshots = Default::default();
        self.num_inputs = Default::default();
        self.num_hangs = Default::default();
        self.num_crashes = Default::default();

        self.start_time = Default::default();
        self.track_time = Default::default();
        self.snapshot_time = Default::default();

        self.hist_execs_per_snap_cond = Histogram::new_from(&self.hist_execs_per_snap_cond);
        self.hist_execs_per_snapshot = Histogram::new_from(&self.hist_execs_per_snapshot);
        self.hist_delayed_execs_micros = Histogram::new_from(&self.hist_delayed_execs_micros);
        self.hist_plain_execs_micros = Histogram::new_from(&self.hist_plain_execs_micros);
        self.hist_track_micros = Histogram::new_from(&self.hist_track_micros);
        self.hist_snapshot_micros = Histogram::new_from(&self.hist_snapshot_micros);

        // `snapshot_threshold` is not cleared, it is updated when syncing.
    }

    pub fn find_new(&mut self, status: &StatusType) {
        match status {
            StatusType::Normal(_) => {
                self.num_inputs.count();
            },
            StatusType::Timeout => {
                self.num_hangs.count();
            },
            StatusType::Crash => {
                self.num_crashes.count();
            },
            _ => {},
        }
    }
}
