use super::{forksrv::DelayedForkServerFactory, limit::SetLimit, test_case_shm::TestCaseShm, *};

use crate::{
    branches, command,
    cond_stmt::{self, NextState},
    depot,
    fuzz_main::XRayMap,
    stats::{self, TimeIns},
    track,
};
use angora_common::{config, defs};

use rand::prelude::*;
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, RwLock,
    },
    time::{self, Duration, Instant},
};
use wait_timeout::ChildExt;

/// This structure takes care of running the program under test in all its
/// instrumentation flavors. For each run performed, it will also additionally
/// analyze the test case if deemed interesting and update the internal state of
/// the fuzzer accordingly. It is independent from the condition currently being
/// targeted.

pub struct Executor {
    cmd: command::CommandOpt,
    branches: branches::Branches,
    t_conds: cond_stmt::ShmConds,
    shared_test_case: TestCaseShm,
    envs: HashMap<OsString, OsString>,
    forksrv: Option<Forksrv>,
    delayed_fork_server_factory: Option<DelayedForkServerFactory>,
    current_delayed_fork_server: Option<Forksrv>, // Should be dropped before the factory.
    delayed_fork_server_failed: bool,
    depot: Arc<depot::Depot>,
    fd: PipeFd,
    tmout_cnt: usize,
    invariable_cnt: usize,
    pub last_f: u64,
    pub has_new_path: bool,
    global_stats: Arc<RwLock<stats::ChartStats>>,
    pub local_stats: stats::LocalStats,
    xray_maps: (XRayMap, XRayMap),
}

impl Executor {
    pub fn new(
        cmd: command::CommandOpt,
        global_branches: Arc<branches::GlobalBranches>,
        depot: Arc<depot::Depot>,
        global_stats: Arc<RwLock<stats::ChartStats>>,
        xray_maps: (XRayMap, XRayMap),
    ) -> Self {
        // ** Share Memory **
        let branches = branches::Branches::new(global_branches);
        let t_conds = cond_stmt::ShmConds::new();
        let shared_test_case = TestCaseShm::new();

        // ** Envs **
        let mut envs = HashMap::new();
        envs.insert(
            OsString::from(defs::ASAN_OPTIONS_VAR),
            OsString::from(defs::ASAN_OPTIONS_CONTENT),
        );
        envs.insert(
            OsString::from(defs::MSAN_OPTIONS_VAR),
            OsString::from(defs::MSAN_OPTIONS_CONTENT),
        );
        envs.insert(
            OsString::from(defs::BRANCHES_SHM_ENV_VAR),
            branches.get_id().to_string().into(),
        );
        envs.insert(
            OsString::from(defs::COND_STMT_ENV_VAR),
            t_conds.get_id().to_string().into(),
        );
        envs.insert(
            OsString::from(defs::INPUT_FILE_ENV_VAR),
            cmd.out_file.clone().into(),
        );

        if let Some(rust_log_value) = env::var_os(defs::RUST_LOG_VARNAME) {
            envs.insert(OsString::from(defs::RUST_LOG_VARNAME), rust_log_value);
        }

        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = Some(
            forksrv::Forksrv::new(
                &cmd.forksrv_socket_path,
                &cmd.main,
                &envs,
                fd.as_raw_fd(),
                cmd.is_stdin,
                cmd.uses_asan,
                cmd.time_limit,
                cmd.mem_limit,
            )
            .expect("Failed to initialize fork server"),
        );

        let delayed_fork_server_factory = DelayedForkServerFactory::new(
            &cmd.delayed_forksrv_tmp_dir,
            &cmd.snapshot_placement_target,
            &cmd.dfsan_snapshot_target,
            &cmd.xray_snapshot_target,
            &envs,
            &cmd.out_file,
            shared_test_case.get_id(),
            xray_maps.clone(),
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
        )
        .expect("Failed to initialize delayed fork server factory");

        let local_stats = global_stats.read().unwrap().local_stats();

        Self {
            cmd,
            branches,
            t_conds,
            shared_test_case,
            envs,
            forksrv,
            delayed_fork_server_factory: Some(delayed_fork_server_factory),
            current_delayed_fork_server: None,
            delayed_fork_server_failed: false,
            depot,
            fd,
            tmout_cnt: 0,
            invariable_cnt: 0,
            last_f: defs::UNREACHABLE,
            has_new_path: false,
            global_stats,
            local_stats,
            xray_maps,
        }
    }

    /// Stop the previuos fork server and start a new one.
    pub fn rebind_forksrv(&mut self) {
        {
            // delete the old forksrv
            self.forksrv = None;
        }
        let fs = forksrv::Forksrv::new(
            &self.cmd.forksrv_socket_path,
            &self.cmd.main,
            &self.envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit,
            self.cmd.mem_limit,
        )
        .expect("Failed to reinitialize fork server");
        self.forksrv = Some(fs);
    }

    fn maybe_start_delayed_fork_server(&mut self, test_case: &[u8], cond: &cond_stmt::CondStmt) {
        if self.local_stats.fuzz_type.modifies_tainted_only()
            && self.current_delayed_fork_server.is_none()
            && !self.delayed_fork_server_failed
        {
            if self.cmd.ignore_snapshot_threshold {
                log::debug!("Ignoring snapshot threshold");
                if !self.start_delayed_fork_server(test_case, cond) {
                    self.delayed_fork_server_failed = true;
                }
            } else if let Some(snapshot_threshold) = self.local_stats.snapshot_threshold {
                if self.local_stats.num_exec.0 as u64 >= snapshot_threshold {
                    if !self.start_delayed_fork_server(test_case, cond) {
                        self.delayed_fork_server_failed = true;
                    }
                }
            }
        }
    }

    fn start_delayed_fork_server(&mut self, test_case: &[u8], cond: &cond_stmt::CondStmt) -> bool {
        if test_case.len() > config::TEST_CASE_SHM_SIZE {
            log::warn!("Test case too big, delayed fork server cannot be used");
            self.current_delayed_fork_server = None;
            return false;
        }

        let snapshot_start = TimeIns::default();

        self.t_conds.set(cond);
        self.write_test(test_case);

        match self
            .delayed_fork_server_factory
            .as_mut()
            .unwrap()
            .build(&cond.offsets, self.local_stats.current_test_case)
        {
            Ok(Some((new_delayed_fork_server, target_info))) => {
                self.current_delayed_fork_server = Some(new_delayed_fork_server);
                self.local_stats.current_snapshot_position = Some(target_info);
            },
            Ok(None) => {
                log::error!("Cached snapshot failure for test case {}", cond.base.belong);
                self.current_delayed_fork_server = None;

                let snapshot_time = snapshot_start.elapsed();
                self.local_stats.snapshot_time += snapshot_time;
                self.local_stats.hist_snapshot_micros += snapshot_time.0.as_micros() as u64;
                log::error!(
                    "Time wasted on cached snapshot failure: {:?}",
                    snapshot_time.0
                );

                return false;
            },
            Err(error) => {
                log::error!(
                    "Could not initialize new delayed fork server for test case {}: {:#}",
                    cond.base.belong,
                    error
                );
                self.current_delayed_fork_server = None;

                let analysis_cache = self
                    .delayed_fork_server_factory
                    .as_mut()
                    .unwrap()
                    .take_analysis_cache();

                // Drop old factory first, so that the directories gets cleaned.
                self.delayed_fork_server_factory = None;

                log::error!("Reinitializing delayed fork server factory");
                self.delayed_fork_server_factory = Some(
                    DelayedForkServerFactory::new(
                        &self.cmd.delayed_forksrv_tmp_dir,
                        &self.cmd.snapshot_placement_target,
                        &self.cmd.dfsan_snapshot_target,
                        &self.cmd.xray_snapshot_target,
                        &self.envs,
                        &self.cmd.out_file,
                        self.shared_test_case.get_id(),
                        self.xray_maps.clone(),
                        self.fd.as_raw_fd(),
                        self.cmd.is_stdin,
                        self.cmd.uses_asan,
                        self.cmd.time_limit,
                        self.cmd.mem_limit,
                    )
                    .expect("Failed to reinitialize delayed fork server factory"),
                );
                self.delayed_fork_server_factory
                    .as_mut()
                    .unwrap()
                    .set_analysis_cache(analysis_cache);

                let snapshot_time = snapshot_start.elapsed();
                self.local_stats.snapshot_time += snapshot_time;
                self.local_stats.hist_snapshot_micros += snapshot_time.0.as_micros() as u64;
                log::error!(
                    "Time wasted on failed snapshot and reinit: {:?}",
                    snapshot_time.0
                );

                return false;
            },
        };

        // The snapshot should always be taken before the target condition is
        // reached. If that is not the case, the condition will never be
        // influenced by the new test cases.
        if self.t_conds.is_cond_reachable() {
            log::error!("Snapshot taken after triggering target condition!");
            log::error!(
                "Target condition: (id: {}, ctx: {}, order: {})",
                cond.base.cmpid,
                cond.base.context,
                cond.base.order
            );
            log::error!("Falling back to plain fork server");
            self.current_delayed_fork_server = None;

            let snapshot_time = snapshot_start.elapsed();
            self.local_stats.snapshot_time += snapshot_time;
            self.local_stats.hist_snapshot_micros += snapshot_time.0.as_micros() as u64;
            log::error!("Time wasted on failed snapshot: {:?}", snapshot_time.0);

            return false;
        }

        let snapshot_time = snapshot_start.elapsed();
        self.local_stats.snapshot_time += snapshot_time;
        self.local_stats.hist_snapshot_micros += snapshot_time.0.as_micros() as u64;
        self.local_stats.num_snapshots.count();

        true
    }

    fn stop_delayed_fork_server(&mut self) {
        if let Some(current_delayed_fork_server) = self.current_delayed_fork_server.as_ref() {
            log::debug!(
                "Delayed fork server was used for {} executions.",
                current_delayed_fork_server.execs().0
            );
            self.local_stats.hist_execs_per_snapshot +=
                current_delayed_fork_server.execs().0 as u64;
        }

        self.current_delayed_fork_server = None;
        self.delayed_fork_server_failed = false;
    }

    // FIXME: The location id may be inconsistent between track and fast programs.
    fn check_consistent(&self, output: u64, cond: &mut cond_stmt::CondStmt) {
        if output == defs::UNREACHABLE
            && cond.is_first_time()
            && self.local_stats.num_exec == 1.into()
            && cond.state.is_initial()
        {
            cond.is_consistent = false;
            warn!("inconsistent : {:?}", cond);
        }
    }

    // Check if, based on `output`, the arguments of `cond` cannot be changed.
    fn check_invariable(&mut self, output: u64, cond: &mut cond_stmt::CondStmt) -> bool {
        let mut skip = false;
        if output == self.last_f {
            self.invariable_cnt += 1;
            if self.invariable_cnt >= config::MAX_INVARIABLE_NUM {
                debug!("output is invariable! f: {}", output);
                if cond.is_desirable {
                    cond.is_desirable = false;
                }
                // deterministic will not skip
                if !cond.state.is_det() && !cond.state.is_one_byte() {
                    skip = true;
                }
            }
        } else {
            self.invariable_cnt = 0;
        }
        self.last_f = output;
        skip
    }

    // Check if, based on `output`, `cond` has been explored.
    fn check_explored(
        &self,
        cond: &mut cond_stmt::CondStmt,
        _status: StatusType,
        output: u64,
        explored: &mut bool,
    ) -> bool {
        let mut skip = false;
        // If crash or timeout, constraints after the point won't be tracked.
        if output == 0 && !cond.is_done()
        //&& status == StatusType::Normal
        {
            debug!("Explored this condition!");
            skip = true;
            *explored = true;
            cond.mark_as_done();
        }
        skip
    }

    /// Run test case in `buf` returning the value to be minimized in order to
    /// flip `cond`. Update internal state according to findings.
    pub fn run_with_cond(
        &mut self,
        buf: &Vec<u8>,
        cond: &mut cond_stmt::CondStmt,
    ) -> (StatusType, u64) {
        self.maybe_start_delayed_fork_server(buf, cond);

        self.run_init();
        self.t_conds.set(cond);
        let mut status = self.run_inner(buf);

        let output = self.t_conds.get_cond_output();
        let mut explored = false;
        let mut skip = false;
        skip |= self.check_explored(cond, status, output, &mut explored);
        skip |= self.check_invariable(output, cond);
        self.check_consistent(output, cond);

        self.do_if_has_new(buf, status, explored, cond.base.cmpid);

        status = self.check_timeout(status, cond);

        if skip {
            status = StatusType::Skip;
        }

        (status, output)
    }

    /// Check if test case in `buf` behaves differently with unlimited memory.
    fn try_unlimited_memory(&mut self, buf: &Vec<u8>, cmpid: u32) -> bool {
        let mut skip = false;
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        compiler_fence(Ordering::SeqCst);
        let unmem_status =
            self.run_target(&self.cmd.main, config::MEM_LIMIT_TRACK, self.cmd.time_limit);
        compiler_fence(Ordering::SeqCst);

        // find difference
        if !matches!(unmem_status, StatusType::Normal(_)) {
            skip = true;
            warn!(
                "Behavior changes if we unlimit memory!! status={:?}",
                unmem_status
            );
            // crash or hang
            if self.branches.has_new(unmem_status, true).0 {
                self.depot.save(unmem_status, &buf, cmpid);
            }
        }
        skip
    }

    /// Analyze test case in `buf` if it has obtained new coverage.
    fn do_if_has_new(&mut self, buf: &Vec<u8>, status: StatusType, _explored: bool, cmpid: u32) {
        // new edge: one byte in bitmap
        let (has_new_path, has_new_coverage, edge_num) = self.branches.has_new(status, true);

        if has_new_path {
            self.has_new_path = true;
            self.local_stats.find_new(&status);
            let id = self.depot.save(status, &buf, cmpid);

            if matches!(status, StatusType::Normal(_)) {
                log::trace!("Analyzing interesting test case: {}", id);

                self.local_stats
                    .avg_edge_num
                    .update(edge_num.unwrap() as f32);
                let speed = self.count_time();
                let speed_ratio = self.local_stats.avg_exec_time.get_ratio(speed as f32);
                self.local_stats.avg_exec_time.update(speed as f32);

                // Avoid track slow ones
                if (!has_new_coverage && speed_ratio > 10 && id > 10)
                    || (speed_ratio > 25 && id > 10)
                {
                    log::warn!(
                        "Skip tracking id {}, speed: {}, speed_ratio: {}, has_new_edge: {}",
                        id,
                        speed,
                        speed_ratio,
                        has_new_coverage
                    );
                    return;
                }

                let crash_or_tmout = self.try_unlimited_memory(buf, cmpid);
                if !crash_or_tmout {
                    log::trace!("Analyzing test case with track instrumentation: {}", id);
                    let cond_stmts = self.track(id, buf, speed);
                    log::debug!(
                        "Track analysis encountered {} conditions.",
                        cond_stmts.len()
                    );
                    if cond_stmts.len() > 0 {
                        self.depot.add_entries(cond_stmts);
                        if self.cmd.enable_afl {
                            self.depot
                                .add_entries(vec![cond_stmt::CondStmt::get_afl_cond(
                                    id,
                                    speed,
                                    edge_num.unwrap(),
                                )]);
                        }
                    }
                }
            }
        }
    }

    /// Run test case in `buf`. Update internal state according to findings.
    pub fn run(&mut self, buf: &Vec<u8>, cond: &mut cond_stmt::CondStmt) -> StatusType {
        self.maybe_start_delayed_fork_server(buf, cond);

        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, status, false, 0);
        self.check_timeout(status, cond)
    }

    /// Run test case in `buf`. Update internal state according to findings. This
    /// function is used when no related condition is available (e.g. when
    /// importing test cases from other fuzzers).
    pub fn run_sync(&mut self, buf: &Vec<u8>) {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, status, false, 0);
    }

    fn run_init(&mut self) {
        self.has_new_path = false;
        self.local_stats.num_exec.count();
    }

    /// Update timeout info in `cond` according to `status`.
    fn check_timeout(&mut self, status: StatusType, cond: &mut cond_stmt::CondStmt) -> StatusType {
        let mut ret_status = status;

        if ret_status == StatusType::Timeout {
            self.tmout_cnt = self.tmout_cnt + 1;
            if self.tmout_cnt >= config::TMOUT_SKIP {
                cond.to_timeout();
                ret_status = StatusType::Skip;
                self.tmout_cnt = 0;
            }
        } else {
            self.tmout_cnt = 0;
        };

        ret_status
    }

    /// Run test case with coverage tracing instrumentation. The run happens in
    /// the fork server if available.
    fn run_inner(&mut self, buf: &Vec<u8>) -> StatusType {
        self.write_test(buf);

        compiler_fence(Ordering::SeqCst);
        let ret_status = match (
            self.current_delayed_fork_server.as_mut(),
            self.forksrv.as_mut(),
        ) {
            (Some(delayed_fork_server), _) if self.shared_test_case.set_content(buf).is_ok() => {
                log::trace!("Running with delayed fork server");

                // The trace should be restored to what it was at the moment of
                // the snapshot. However, this adds a substantial performance
                // overhead to snapshot restores. A trace clearing is used as a
                // significantly faster approximation.

                let exec_begin = Instant::now();
                let status = delayed_fork_server
                    .run()
                    .expect("Could not start child from delayed fork server");
                self.local_stats.hist_delayed_execs_micros +=
                    exec_begin.elapsed().as_micros() as u64;

                status
            },
            (_, Some(fork_server)) => {
                log::trace!("Running with plain fork server");

                let exec_begin = Instant::now();
                let status = fork_server.run();

                // Ignore executions from AFL mutators, since they produce a different distribution
                if self.local_stats.fuzz_type.modifies_tainted_only() {
                    self.local_stats.hist_plain_execs_micros +=
                        exec_begin.elapsed().as_micros() as u64;
                }

                match status {
                    Ok(status) => status,
                    Err(error) => {
                        log::warn!(
                            "Could not spawn child from main fork server, rebinding: {:#}",
                            error
                        );
                        self.rebind_forksrv();
                        StatusType::Timeout
                    },
                }
            },
            _ => {
                log::trace!("Running without fork server");
                self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit)
            },
        };
        compiler_fence(Ordering::SeqCst);

        ret_status
    }

    /// Run last test case multiple times and return the average microseconds for a single run.
    fn count_time(&mut self) -> u32 {
        let t_start = time::Instant::now();
        for _ in 0..3 {
            if self.cmd.is_stdin {
                self.fd.rewind();
            }
            if let Some(ref mut fs) = self.forksrv {
                if let Err(error) = fs.run() {
                    log::warn!(
                        "Could not spawn child from main fork server, rebinding: {:#}",
                        error
                    );
                    self.rebind_forksrv();
                    return defs::SLOW_SPEED;
                }
            } else {
                self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit);
            }
        }
        let used_t = t_start.elapsed();
        let used_us = (used_t.as_secs() as u32 * 1000_000) + used_t.subsec_nanos() / 1_000;
        used_us / 3
    }

    /// Run DFSan tracing binary on test case with ID `id` and content in `buf`.
    /// `speed` contains the time it takes to run this test case using the fork
    /// server.
    fn track(&mut self, id: usize, buf: &Vec<u8>, speed: u32) -> Vec<cond_stmt::CondStmt> {
        self.envs.insert(
            OsString::from(defs::TRACK_OUTPUT_VAR),
            self.cmd.track_path.clone().into(),
        );

        let track_start: stats::TimeIns = Default::default();

        self.write_test(buf);

        compiler_fence(Ordering::SeqCst);
        let ret_status = self.run_target(
            &self.cmd.track,
            config::MEM_LIMIT_TRACK,
            config::TIME_LIMIT_TRACK,
        );
        compiler_fence(Ordering::SeqCst);

        if !matches!(ret_status, StatusType::Normal(_)) {
            log::error!(
                "Crash or hang while tracking! -- {:?},  id: {}",
                ret_status,
                id
            );

            let track_time = track_start.elapsed();
            self.local_stats.track_time += track_time;
            self.local_stats.hist_track_micros += track_time.0.as_micros() as u64;

            return Vec::new();
        }

        let cond_list = track::load_track_data(
            Path::new(&self.cmd.track_path),
            id as u32,
            speed,
            self.cmd.mode.is_pin_mode(),
            self.cmd.enable_exploitation,
        );

        let track_time = track_start.elapsed();
        self.local_stats.track_time += track_time;
        self.local_stats.hist_track_micros += track_time.0.as_micros() as u64;

        cond_list
    }

    /// Get a random test case from storage.
    pub fn random_input_buf<R: Rng + ?Sized>(&self, rng: &mut R) -> Vec<u8> {
        let id = self.depot.next_random(rng);
        self.depot.get_input_buf(id)
    }

    /// Write data in `buf` to target program input file.
    fn write_test(&mut self, buf: &[u8]) {
        self.fd.write_buf(buf);
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
    }

    /// Execute program in `target.0` with arguments in `target.1`.
    fn run_target(
        &self,
        target: &(PathBuf, Vec<OsString>),
        mem_limit: u64,
        time_limit: Duration,
    ) -> StatusType {
        let (stdout_redirect, stderr_redirect) = if log::log_enabled!(log::Level::Info) {
            if log::log_enabled!(log::Level::Trace) {
                (Stdio::inherit(), Stdio::inherit())
            } else {
                (Stdio::null(), Stdio::inherit())
            }
        } else {
            (Stdio::null(), Stdio::null())
        };

        let mut child = Command::new(&target.0)
            .args(&target.1)
            .stdin(Stdio::null())
            .envs(&self.envs)
            .stdout(stdout_redirect)
            .stderr(stderr_redirect)
            .mem_limit(mem_limit)
            .block_core_files()
            .setsid()
            .pipe_stdin(self.fd.as_raw_fd(), self.cmd.is_stdin)
            .spawn()
            .expect("Could not run target");

        let ret = match child.wait_timeout(time_limit).unwrap() {
            Some(status) => {
                if let Some(status_code) = status.code() {
                    if (self.cmd.uses_asan && status_code == defs::MSAN_ERROR_CODE)
                        || (self.cmd.mode.is_pin_mode() && status_code > 128)
                    {
                        StatusType::Crash
                    } else {
                        StatusType::Normal(Some(status_code))
                    }
                } else {
                    StatusType::Crash
                }
            },
            None => {
                // Timeout
                // child hasn't exited yet
                child.kill().expect("Could not send kill signal to child.");
                child.wait().expect("Error during waiting for child.");
                StatusType::Timeout
            },
        };
        ret
    }

    /// Update global stats with collected local data.
    pub fn update_log(&mut self) {
        self.stop_delayed_fork_server();

        if self.local_stats.fuzz_type.modifies_tainted_only() {
            self.local_stats.hist_execs_per_snap_cond += self.local_stats.num_exec.0 as u64;
        }

        self.global_stats
            .write()
            .unwrap()
            .sync_from_local(&mut self.local_stats);

        self.t_conds.clear();
        self.tmout_cnt = 0;
        self.invariable_cnt = 0;
        self.last_f = defs::UNREACHABLE;
    }
}
