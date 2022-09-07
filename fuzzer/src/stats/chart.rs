use super::*;
use crate::{branches::GlobalBranches, depot::Depot};
use colored::*;
use serde::Serialize;
use std::sync::Arc;

/// Contribution of new speed update to displayed speed
const SPEED_SMOOTHING_PERC: f32 = 0.10;

/// Significant speed change factor
const SPEED_JUMP_FACTOR: f32 = 5_f32;

#[derive(Default, Serialize)]
pub struct ChartStats {
    init_time: TimeIns,
    track_time: TimeDuration,
    density: Average,

    num_rounds: Counter,
    max_rounds: Counter,
    num_exec: Counter,

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
}

impl ChartStats {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn sync_from_local(&mut self, local: &mut LocalStats) {
        self.track_time += local.track_time;
        self.num_rounds.count();

        local.avg_edge_num.sync(&mut self.avg_edge_num);
        local.avg_exec_time.sync(&mut self.avg_exec_time);

        let st = self.fuzz.get_mut(local.fuzz_type.index());
        st.time += local.start_time.elapsed();
        // st.num_conds.count();

        st.num_exec += local.num_exec;
        self.num_exec += local.num_exec;
        // if has new
        st.num_inputs += local.num_inputs;
        self.num_inputs += local.num_inputs;
        st.num_hangs += local.num_hangs;
        self.num_hangs += local.num_hangs;
        st.num_crashes += local.num_crashes;
        self.num_crashes += local.num_crashes;

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
            "{},{},{},{},{},{}",
            "elapsed_secs",
            "num_execs",
            "density",
            "num_normal_test_cases",
            "num_hang_test_cases",
            "num_crash_test_cases"
        )
    }

    pub fn mini_log(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.init_time.0.elapsed().as_secs(),
            self.num_exec.0,
            self.density.0,
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
            "     TIME  |     TOTAL: {}, TRACK: {}",
            self.init_time, self.track_time,
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
            "    SPEED  |     {:6} exec/s, EST_EXEC_TIME: {} us",
            self.speed, self.avg_exec_time,
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
