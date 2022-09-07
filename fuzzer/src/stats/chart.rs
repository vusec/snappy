use super::*;
use crate::{branches::GlobalBranches, depot::Depot, executor::TargetHookInfo};
use colored::*;
use hdrhistogram::Histogram;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

const SNAPSHOT_THRESHOLD_UPDATE_INTERVAL: Duration = Duration::from_secs(60);
const SNAPSHOT_THRESHOLD_INIT: u64 = 0;

const DECAY_INTERVAL: Duration = Duration::from_secs(60 * 15);
const DECAY_FACTOR: f64 = 0.85;

const RESAMPLE_INTERVAL: Duration = Duration::from_secs(60 * 5);
const RESAMPLE_AMOUNT: u64 = 500;

/// Contribution of new speed update to displayed speed
const SPEED_SMOOTHING_PERC: f32 = 0.10;

/// Significant speed change factor
const SPEED_JUMP_FACTOR: f32 = 5_f32;

type SnapshotPositionStats = HashMap<(TargetHookInfo, u64), u64>;

#[derive(Serialize)]
pub struct ChartStats {
    init_time: TimeIns,
    track_time: TimeDuration,
    snapshot_time: TimeDuration,
    density: Average,

    num_rounds: Counter,
    max_rounds: Counter,
    num_exec: Counter,
    num_snapshots: Counter,

    speed: Average,
    last_speed_update_time: TimeIns,
    last_speed_update_execs: Counter,

    avg_exec_time: Average,
    avg_edge_num: Average,

    num_inputs: Counter,
    num_hangs: Counter,
    num_crashes: Counter,

    fuzz: FuzzStats,
    search: SearchStats,
    state: StateStats,

    #[serde(skip_serializing)]
    hist_execs_per_snap_cond: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_execs_per_snap_cond_decay: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_execs_per_snapshot: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_delayed_execs_micros: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_plain_execs_micros: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_track_micros: Histogram<u64>,
    #[serde(skip_serializing)]
    hist_snapshot_micros: Histogram<u64>,

    snapshot_threshold: Option<u64>,
    #[serde(skip_serializing)]
    snapshot_threshold_last_update: Instant,

    #[serde(skip_serializing)]
    last_decay: Instant,

    #[serde(skip_serializing)]
    last_resample: Instant,
    #[serde(skip_serializing)]
    plain_since_resample: u64,
    #[serde(skip_serializing)]
    delayed_since_resample: u64,

    #[serde(skip_serializing)]
    snapshot_position_stats: SnapshotPositionStats,
}

impl ChartStats {
    pub fn new() -> Self {
        Self {
            init_time: Default::default(),
            track_time: Default::default(),
            snapshot_time: Default::default(),
            density: Default::default(),

            num_rounds: Default::default(),
            max_rounds: Default::default(),
            num_exec: Default::default(),
            num_snapshots: Default::default(),

            speed: Default::default(),
            last_speed_update_time: Default::default(),
            last_speed_update_execs: Default::default(),

            avg_exec_time: Default::default(),
            avg_edge_num: Default::default(),

            num_inputs: Default::default(),
            num_hangs: Default::default(),
            num_crashes: Default::default(),

            fuzz: Default::default(),
            search: Default::default(),
            state: Default::default(),

            hist_execs_per_snap_cond: Histogram::new(2).unwrap().into(),
            hist_execs_per_snap_cond_decay: Histogram::new(2).unwrap().into(),
            hist_execs_per_snapshot: Histogram::new(2).unwrap().into(),
            hist_delayed_execs_micros: Histogram::new(2).unwrap().into(),
            hist_plain_execs_micros: Histogram::new(2).unwrap().into(),
            hist_track_micros: Histogram::new(2).unwrap().into(),
            hist_snapshot_micros: Histogram::new(2).unwrap().into(),

            snapshot_threshold: Some(SNAPSHOT_THRESHOLD_INIT),
            snapshot_threshold_last_update: Instant::now(),

            last_decay: Instant::now(),

            last_resample: Instant::now(),
            plain_since_resample: 0,
            delayed_since_resample: 0,

            snapshot_position_stats: Default::default(),
        }
    }

    fn get_snapshot_benefit(&self, current_threshold: u64, ammort_execs: u64) -> f64 {
        let mut benefit = 0_f64;

        for iter_value in self.hist_execs_per_snap_cond_decay.iter_recorded() {
            if iter_value.value_iterated_to() < current_threshold {
                continue;
            }

            benefit += (iter_value.value_iterated_to() as f64
                - (current_threshold as f64 + ammort_execs as f64))
                * iter_value.count_since_last_iteration() as f64;
        }

        benefit
    }

    fn maybe_trigger_hist_decay(&mut self) {
        if self.last_decay.elapsed() < DECAY_INTERVAL {
            return;
        }

        log::debug!("Triggering histogram decay by {}%", DECAY_FACTOR * 100_f64);

        let mut decayed_hist = Histogram::new_from(&self.hist_execs_per_snap_cond_decay);
        for iter_value in self.hist_execs_per_snap_cond_decay.iter_recorded() {
            let new_count = iter_value.count_at_value() as f64 * DECAY_FACTOR;
            decayed_hist
                .record_n(iter_value.value_iterated_to(), new_count.round() as u64)
                .unwrap();
        }
        self.hist_execs_per_snap_cond_decay
            .set_to(decayed_hist)
            .unwrap();

        self.last_decay = Instant::now();
    }

    fn maybe_update_snapshot_threshold(&mut self) {
        if self.snapshot_threshold_last_update.elapsed() < SNAPSHOT_THRESHOLD_UPDATE_INTERVAL {
            return;
        }

        let threshold_update_begin = Instant::now();

        let plain_execs_micros = self.hist_plain_execs_micros.value_at_quantile(0.5);
        let delayed_execs_micros = self.hist_delayed_execs_micros.value_at_quantile(0.5);
        let snapshot_micros = self.hist_snapshot_micros.value_at_quantile(0.5);

        log::debug!("Median plain execs: {}", plain_execs_micros);
        log::debug!("Median delayed execs: {}", delayed_execs_micros);
        log::debug!("Median snapshot time: {}", snapshot_micros);

        if plain_execs_micros <= delayed_execs_micros {
            self.snapshot_threshold = None;
            self.snapshot_threshold_last_update = Instant::now();
            log::warn!("Snapshotted executions are slower than plain ones");
            return;
        }

        let ammort_execs = snapshot_micros / (plain_execs_micros - delayed_execs_micros);
        log::debug!("Execs to ammortize snapshot: {}", ammort_execs);

        let upper_execs_per_snap_cond = self.hist_execs_per_snap_cond_decay.value_at_quantile(0.99);

        let mut max_benefit = f64::MIN; // Should be 0, but always pick a threshold.
        let mut best_threshold = None;
        for current_threshold in (0..upper_execs_per_snap_cond).step_by(5) {
            let current_benefit = self.get_snapshot_benefit(current_threshold, ammort_execs);
            log::trace!("Benefit for {}:\t{}", current_threshold, current_benefit);
            if max_benefit < current_benefit {
                max_benefit = current_benefit;
                best_threshold = Some(current_threshold);
            }
        }

        if max_benefit < 0_f64 && best_threshold.is_some() {
            log::warn!(
                "Snapshot benefit may be negative with threshold {}, using anyway.",
                best_threshold.unwrap()
            );
        }

        self.snapshot_threshold = best_threshold;
        self.snapshot_threshold_last_update = Instant::now();

        log::debug!(
            "Snapshot threshold update took: {:?}",
            threshold_update_begin.elapsed()
        );
        log::info!("Snapshot threshold is now: {:?}", self.snapshot_threshold);
    }

    // Each `RESAMPLE_INTERVAL`, at least `RESAMPLE_AMOUNT` executions of
    // each kind should be recorded.
    fn get_next_threshold(&mut self) -> Option<u64> {
        if self.last_resample.elapsed() > RESAMPLE_INTERVAL {
            self.last_resample = Instant::now();
            self.plain_since_resample = 0;
            self.delayed_since_resample = 0;
        } else if self.plain_since_resample > RESAMPLE_AMOUNT
            && self.delayed_since_resample > RESAMPLE_AMOUNT
        {
            return self.snapshot_threshold;
        }

        let next_threshold = if self.plain_since_resample < self.delayed_since_resample {
            None
        } else {
            Some(0)
        };

        log::debug!("Using resampling threshold: {:?}", next_threshold);

        next_threshold
    }

    pub fn local_stats(&self) -> LocalStats {
        LocalStats {
            fuzz_type: Default::default(),
            current_test_case: Default::default(),
            current_snapshot_position: Default::default(),

            num_exec: Default::default(),
            num_snapshots: Default::default(),
            num_inputs: Default::default(),
            num_hangs: Default::default(),
            num_crashes: Default::default(),

            track_time: Default::default(),
            snapshot_time: Default::default(),
            start_time: Default::default(),

            avg_exec_time: Default::default(),
            avg_edge_num: Default::default(),

            hist_execs_per_snap_cond: Histogram::new_from(&self.hist_execs_per_snap_cond),
            hist_execs_per_snapshot: Histogram::new_from(&self.hist_execs_per_snapshot),
            hist_delayed_execs_micros: Histogram::new_from(&self.hist_delayed_execs_micros),
            hist_plain_execs_micros: Histogram::new_from(&self.hist_plain_execs_micros),
            hist_track_micros: Histogram::new_from(&self.hist_track_micros),
            hist_snapshot_micros: Histogram::new_from(&self.hist_snapshot_micros),

            snapshot_threshold: self.snapshot_threshold,
        }
    }

    pub fn sync_from_local(&mut self, local: &mut LocalStats) {
        self.track_time += local.track_time;
        self.snapshot_time += local.snapshot_time;
        self.num_rounds.count();

        local.avg_edge_num.sync(&mut self.avg_edge_num);
        local.avg_exec_time.sync(&mut self.avg_exec_time);

        let st = self.fuzz.get_mut(local.fuzz_type.index());
        st.time += local.start_time.elapsed();
        // st.num_conds.count();

        st.num_exec += local.num_exec;
        self.num_exec += local.num_exec;
        self.num_snapshots += local.num_snapshots;
        // if has new
        st.num_inputs += local.num_inputs;
        self.num_inputs += local.num_inputs;
        st.num_hangs += local.num_hangs;
        self.num_hangs += local.num_hangs;
        st.num_crashes += local.num_crashes;
        self.num_crashes += local.num_crashes;

        self.hist_execs_per_snap_cond
            .add(&local.hist_execs_per_snap_cond)
            .expect("Histogram merge failed");
        self.hist_execs_per_snap_cond_decay
            .add(&local.hist_execs_per_snap_cond)
            .expect("Histogram merge failed");
        self.hist_execs_per_snapshot
            .add(&local.hist_execs_per_snapshot)
            .expect("Histogram merge failed");
        self.hist_delayed_execs_micros
            .add(&local.hist_delayed_execs_micros)
            .expect("Histogram merge failed");
        self.hist_plain_execs_micros
            .add(&local.hist_plain_execs_micros)
            .expect("Histogram merge failed");
        self.hist_track_micros
            .add(&local.hist_track_micros)
            .expect("Histogram merge failed");
        self.hist_snapshot_micros
            .add(&local.hist_snapshot_micros)
            .expect("Histogram merge failed");

        self.plain_since_resample += local.hist_plain_execs_micros.len();
        self.delayed_since_resample += local.hist_delayed_execs_micros.len();

        self.maybe_update_snapshot_threshold();
        self.maybe_trigger_hist_decay();
        local.snapshot_threshold = self.get_next_threshold();

        if let Some(current_snapshot_position) = &local.current_snapshot_position {
            let counter = self
                .snapshot_position_stats
                .entry((current_snapshot_position.clone(), local.current_test_case))
                .or_insert(0);
            *counter += 1;
        }

        //local.clear();
    }

    pub fn sync_from_global(&mut self, depot: &Arc<Depot>, gb: &Arc<GlobalBranches>) {
        self.update_speed();
        self.get_queue_stats(depot);
        self.get_density(gb);
    }

    fn get_queue_stats(&mut self, depot: &Arc<Depot>) {
        let queue = match depot.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Lock poisoned. Results can be incorrect! Continuing...");
                poisoned.into_inner()
            },
        };
        self.search = Default::default();
        self.state = Default::default();
        self.fuzz.clear();
        let mut max_round = 0;
        for (item, _) in queue.iter() {
            if item.fuzz_times > max_round {
                max_round = item.fuzz_times;
            }
            self.fuzz.count(&item);
            if item.base.is_explore() {
                self.search.count(&item);
                self.state.count(&item);
            }
        }
        self.max_rounds = max_round.into();
    }

    fn get_density(&mut self, gb: &Arc<GlobalBranches>) {
        self.density = Average::new(gb.get_density(), 0);
    }

    fn update_speed(&mut self) {
        let update_time = time::Instant::now();
        let time_since_last_update = update_time - self.last_speed_update_time.0;
        let execs_since_last_update = self.num_exec.0 - self.last_speed_update_execs.0;

        let current_speed =
            (execs_since_last_update as f64 / time_since_last_update.as_secs() as f64) as f32;
        if !current_speed.is_finite() {
            // Avoid updating speed if time interval is too short
            return;
        }

        let previous_speed = self.speed.get();
        let new_speed = if current_speed > previous_speed * SPEED_JUMP_FACTOR
            || current_speed < previous_speed / SPEED_JUMP_FACTOR
        {
            // Just reset speed if there is a significant jump
            current_speed
        } else {
            previous_speed * (1_f32 - SPEED_SMOOTHING_PERC) + current_speed * SPEED_SMOOTHING_PERC
        };

        self.last_speed_update_time = TimeIns(update_time);
        self.last_speed_update_execs = self.num_exec;
        self.speed = Average::new(new_speed, 0);
    }

    pub fn mini_log_header(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            "elapsed_secs",
            "num_execs",
            "density",
            "snapshot_threshold",
            "num_normal_test_cases",
            "num_hang_test_cases",
            "num_crash_test_cases"
        )
    }

    pub fn mini_log(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            self.init_time.0.elapsed().as_secs(),
            self.num_exec.0,
            self.density.0,
            if let Some(snapshot_threshold) = self.snapshot_threshold {
                snapshot_threshold.to_string()
            } else {
                "".to_string()
            },
            self.num_inputs.0,
            self.num_hangs.0,
            self.num_crashes.0
        )
    }

    pub fn get_explore_num(&self) -> usize {
        self.fuzz
            .get(fuzz_type::FuzzType::ExploreFuzz.index())
            .num_conds
            .into()
    }

    pub fn hist_execs_per_snap_cond(&self) -> &Histogram<u64> {
        &self.hist_execs_per_snap_cond
    }

    pub fn hist_execs_per_snap_cond_decay(&self) -> &Histogram<u64> {
        &self.hist_execs_per_snap_cond_decay
    }

    pub fn hist_execs_per_snapshot(&self) -> &Histogram<u64> {
        &self.hist_execs_per_snapshot
    }

    pub fn hist_delayed_execs_micros(&self) -> &Histogram<u64> {
        &self.hist_delayed_execs_micros
    }

    pub fn hist_plain_execs_micros(&self) -> &Histogram<u64> {
        &self.hist_plain_execs_micros
    }

    pub fn hist_track_micros(&self) -> &Histogram<u64> {
        &self.hist_track_micros
    }

    pub fn hist_snapshot_micros(&self) -> &Histogram<u64> {
        &self.hist_snapshot_micros
    }

    pub fn snapshot_position_stats(&self) -> &SnapshotPositionStats {
        &self.snapshot_position_stats
    }
}

impl fmt::Display for ChartStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.density.0 > 10.0 {
            log::warn!("Density is too large (> 10%). Please increase `MAP_SIZE_POW2` in and `common/src/config.rs`. Or disable function-call context(density > 50%) by compiling with `ANGORA_CUSTOM_FN_CONTEXT=k` (k is an integer and 0 <= k <= 32) environment variable. Angora disables context if k is 0.");
        }

        if self.search.multiple_inconsist() {
            log::warn!("Multiple inconsistent warnings. It caused by the fast and track programs has different behaviors. If most constraints are inconsistent, ensure they are compiled with the same environment. Otherwise, please report us.");
            // panic()!
        }

        if self.fuzz.may_be_model_failure() {
            log::warn!("Find small number constraints, please make sure you have modeled the read functions.")
        }

        writeln!(f)?;
        writeln!(f, "{}", get_bunny_logo().bold())?;
        writeln!(f, "{}", " -- OVERVIEW -- ".blue().bold())?;
        writeln!(
            f,
            "     TIME  |     TOTAL: {}, TRACK: {}, SNAPSHOT: {}",
            self.init_time, self.track_time, self.snapshot_time,
        )?;
        writeln!(
            f,
            " COVERAGE  | AVG_EDGES: {}, DENSITY: {}%",
            self.avg_edge_num, self.density,
        )?;
        writeln!(
            f,
            "    EXECS  |     TOTAL: {}, TOTAL_ROUNDS: {}, MAX_COND_ROUNDS: {}",
            self.num_exec, self.num_rounds, self.max_rounds,
        )?;
        writeln!(
            f,
            " SNAPSHOT  |     TOTAL: {}, THRES: {:>3}, AVG_EXECS_PER_COND: {}, AVG_SNAP_TIME: {} us",
            self.num_snapshots,
            if let Some(threshold) = self.snapshot_threshold {
                threshold.to_string()
            } else {
                "inf".to_string()
            },
            Average::new(self.hist_execs_per_snap_cond.mean() as f32, 0),
            Average::new(self.hist_snapshot_micros.mean() as f32, 0),
        )?;
        writeln!(
            f,
            "    SPEED  |     {:6} exec/s, AVG_PLAIN_EXEC_TIME: {} us",
            self.speed, self.avg_exec_time
        )?;
        writeln!(
            f,
            "    FOUND  |      PATH: {}, HANGS: {}, CRASHES: {}",
            self.num_inputs, self.num_hangs, self.num_crashes,
        )?;
        writeln!(f, "{}", " -- FUZZ -- ".blue().bold())?;
        writeln!(f, "{}", self.fuzz)?;
        writeln!(f, "{}", " -- SEARCH -- ".blue().bold())?;
        write!(f, "{}", self.search)?;
        writeln!(f, "{}", " -- STATE -- ".blue().bold())?;
        write!(f, "{}", self.state)?;

        Ok(())
    }
}
