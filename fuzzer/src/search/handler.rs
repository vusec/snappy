use super::*;
use crate::stats::Counter;

/// This is a facade object used by mutation operators in order to run new
/// mutated test cases. The mutations are based on a target condition and a test
/// case that leads to it. Each time a new condition is selected, a new
/// `SearchHandler` is constructed as well.
pub struct SearchHandler<'a> {
    running: Arc<AtomicBool>,
    pub executor: &'a mut Executor,
    /// Current target condition.
    pub cond: &'a mut CondStmt,
    /// Mutated test case to be run, initially it leads to `cond` but mutations
    /// can be applied in succession.
    pub buf: Vec<u8>,
    pub max_times: Counter,
    pub skip: bool,
}

impl<'a> SearchHandler<'a> {
    pub fn new(
        running: Arc<AtomicBool>,
        executor: &'a mut Executor,
        cond: &'a mut CondStmt,
        buf: Vec<u8>,
    ) -> Self {
        executor.local_stats.register(cond);
        cond.fuzz_times = cond.fuzz_times + 1;

        Self {
            running,
            executor,
            cond,
            buf,
            max_times: config::MAX_SEARCH_EXEC_NUM.into(),
            skip: false,
        }
    }

    /// Returns if the mutation operator should stop.
    pub fn is_stopped_or_skip(&self) -> bool {
        !self.running.load(Ordering::Relaxed) || self.skip
    }

    fn process_status(&mut self, status: StatusType) {
        match status {
            StatusType::Skip => {
                self.skip = true;
            },
            _ => {},
        }

        // bonus
        if self.executor.has_new_path {
            self.max_times += config::BONUS_EXEC_NUM.into();
        }

        // Skip if it reach max epoch,
        // Like a Round-Robin algorithm,
        // To avoid stuck in some cond too much time.
        if self.executor.local_stats.num_exec > self.max_times {
            self.skip = true;
        }
    }

    /// Execute test case in `buf`.
    pub fn execute(&mut self, buf: &Vec<u8>) {
        let status = self.executor.run(buf, self.cond);
        self.process_status(status);
    }

    /// Execute test case after applying mutations in `input`.
    pub fn execute_input(&mut self, input: &MutInput) {
        input.write_to_input(&self.cond.offsets, &mut self.buf);
        let status = self.executor.run(&self.buf, self.cond);
        self.process_status(status);
    }

    /// Execute test case after applying mutations in `input`.
    ///
    /// This function returns the `u64` to minimize in order to flip the current
    /// target condition.
    pub fn execute_cond(&mut self, input: &MutInput) -> u64 {
        input.write_to_input(&self.cond.offsets, &mut self.buf);
        let (status, f_output) = self.executor.run_with_cond(&self.buf, self.cond);
        self.process_status(status);
        // output will be u64::MAX if unreachable, including timeout and crash
        f_output
    }

    /// Execute last mutated test case.
    ///
    /// This function returns the `u64` to minimize in order to flip the current
    /// target condition.
    pub fn execute_cond_direct(&mut self) -> u64 {
        let (status, f_output) = self.executor.run_with_cond(&self.buf, self.cond);
        self.process_status(status);
        f_output
    }

    /// Execute last mutated test case.
    pub fn execute_input_direct(&mut self) {
        let status = self.executor.run(&self.buf, self.cond);
        self.process_status(status);
    }

    /// Returns a `MutInput` which can be used to mutate the current input based
    /// on the current target condition.
    pub fn get_f_input(&self) -> MutInput {
        debug!("input offset: {:?}", self.cond.offsets);
        MutInput::from(&self.cond.offsets, &self.buf)
    }
}

impl<'a> Drop for SearchHandler<'a> {
    fn drop(&mut self) {
        self.executor.update_log();
    }
}
