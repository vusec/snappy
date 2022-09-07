use super::{
    limit::SetLimit,
    pollable::{PollEvents, Pollable},
    StatusType,
};
use crate::{
    fuzz_main::{FunctionID, XRayMap},
    stats::Counter,
};
use angora_common::{config, defs, tag::TagSeg};

use anyhow::{anyhow, bail, Context};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File},
    io::{prelude::*, BufReader, BufWriter},
    mem::{self, ManuallyDrop},
    os::unix::{
        io::RawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// This structure manages a fork server process. It allows to start it, reset it
/// when needed and spawn new children. It does not handle the input test case,
/// which needs to be set up before spawning new children.
#[derive(Debug)]
pub struct Forksrv {
    socket_path: PathBuf,
    socket: UnixStream,
    process: Option<Child>, // This is Some if the process is a direct child and should be waited
    uses_asan: bool,
    execs: Counter,
}

impl Forksrv {
    pub fn new(
        socket_path: impl AsRef<Path>,
        target: &(PathBuf, Vec<OsString>),
        envs: &HashMap<OsString, OsString>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
    ) -> anyhow::Result<Forksrv> {
        Self::new_with_client_callback(&socket_path, uses_asan, time_limit, || {
            let mut envs_fk = envs.clone();
            envs_fk.insert(OsString::from(defs::ENABLE_FORKSRV), OsString::from("TRUE"));
            envs_fk.insert(
                OsString::from(defs::FORKSRV_SOCKET_PATH_VAR),
                socket_path.as_ref().into(),
            );

            let (stdout_redirect, stderr_redirect) = if log::log_enabled!(log::Level::Info) {
                if log::log_enabled!(log::Level::Trace) {
                    (Stdio::inherit(), Stdio::inherit())
                } else {
                    (Stdio::null(), Stdio::inherit())
                }
            } else {
                (Stdio::null(), Stdio::null())
            };

            let process = Command::new(&target.0)
                .args(&target.1)
                .stdin(Stdio::null())
                .envs(&envs_fk)
                .stdout(stdout_redirect)
                .stderr(stderr_redirect)
                .mem_limit(mem_limit)
                .block_core_files()
                .setsid()
                .pipe_stdin(fd, is_stdin)
                .spawn()
                .context("Failed to spawn child.")?;

            Ok(Some(process))
        })
    }

    /// Construct a new fork server starting the client with the `start_client` callback.
    pub fn new_with_client_callback<F>(
        socket_path: impl AsRef<Path>,
        uses_asan: bool,
        time_limit: Duration,
        start_client: F,
    ) -> anyhow::Result<Forksrv>
    where
        F: FnOnce() -> anyhow::Result<Option<Child>>,
    {
        log::debug!(
            "Waiting for connection on: {:?}",
            socket_path.as_ref().display()
        );
        let listener = UnixListener::bind(&socket_path).context("Failed to bind to socket")?;

        let process = start_client()?;

        log::trace!(
            "Polling for connection request on: {}",
            socket_path.as_ref().display()
        );
        if !listener
            .poll(PollEvents::POLLIN, Some(time_limit))
            .context("Failed to poll on socket")?
        {
            return Err(anyhow!(
                "Child failed to connect to socket: {}",
                socket_path.as_ref().display()
            ));
        }

        log::trace!(
            "Accepting connection on: {}",
            socket_path.as_ref().display()
        );
        let (socket, _) = listener.accept().context("Failed to accept from socket")?;

        socket
            .set_read_timeout(Some(time_limit))
            .expect("Timeout was zero");
        socket
            .set_write_timeout(Some(time_limit))
            .expect("Timeout was zero");

        log::debug!(
            "Fork server initialization successul. Socket: {}",
            socket_path.as_ref().display()
        );

        Ok(Forksrv {
            socket_path: socket_path.as_ref().to_path_buf(),
            socket,
            uses_asan,
            process,
            execs: Counter::default(),
        })
    }

    /// Spawn a new child from the fork server and verify its exit status.
    pub fn run(&mut self) -> anyhow::Result<StatusType> {
        self.execs.count();
        let child_pid = self.spawn()?;

        match self.socket.read_i32::<LittleEndian>() {
            Ok(status) => {
                if libc::WIFSIGNALED(status) {
                    log::debug!("Process signaled: {}", libc::WTERMSIG(status));
                    Ok(StatusType::Crash)
                } else if libc::WIFEXITED(status) {
                    let exit_code = libc::WEXITSTATUS(status);
                    if exit_code == defs::MSAN_ERROR_CODE {
                        log::debug!("Process exited with MSan error");
                        Ok(StatusType::Crash)
                    } else {
                        Ok(StatusType::Normal(Some(exit_code)))
                    }
                } else if libc::WIFSTOPPED(status) {
                    log::debug!("Process stopped for signal: {}", libc::WSTOPSIG(status));
                    Ok(StatusType::Normal(None))
                } else {
                    bail!("Unknown process exit status")
                }
            },
            Err(_) => {
                // Killing the child will cause the fork server process to
                // finally reply with an exit code.
                unsafe {
                    libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
                }

                // Wait for the fork server process to report back that the
                // child has died.
                while self.socket.read_i32::<LittleEndian>().is_err() {
                    log::debug!("Waiting for timed out child to exit");
                }

                Ok(StatusType::Timeout)
            },
        }
    }

    /// Spawn a new child from the fork server without waiting for its
    /// completion.
    pub fn spawn(&mut self) -> anyhow::Result<u32> {
        self.socket.write_i32::<LittleEndian>(1).with_context(|| {
            format!(
                "Failed to write to fork server socket: {}",
                self.socket_path.display()
            )
        })?;

        let child_pid = self.socket.read_i32::<LittleEndian>().with_context(|| {
            format!(
                "Failed to read child PID from socket: {}",
                self.socket_path.display()
            )
        })?;

        if child_pid <= 0 {
            return Err(anyhow!(
                "Invalid child PID ({}) reported from fork server process, socket: {}",
                child_pid,
                self.socket_path.display()
            ));
        }

        Ok(child_pid as u32)
    }

    pub fn execs(&self) -> &Counter {
        &self.execs
    }
}

impl Drop for Forksrv {
    fn drop(&mut self) {
        // Send exit message to child process
        if let Err(error) = self.socket.write_i32::<LittleEndian>(0) {
            log::warn!(
                "Failed to write to socket {}: {}",
                self.socket_path.display(),
                error
            );
        }

        if self.socket_path.exists() {
            if let Err(error) = fs::remove_file(&self.socket_path) {
                log::warn!(
                    "Failed to remove socket {}: {}",
                    self.socket_path.display(),
                    error
                );
            }
        }

        if let Some(process) = self.process.as_mut() {
            log::debug!(
                "Waiting for fork server to exit: {}",
                self.socket_path.display()
            );
            if let Err(error) = process.wait() {
                log::warn!(
                    "Could not wait for fork server {}: {}",
                    self.socket_path.display(),
                    error
                );
            }
        }

        log::debug!("Exited fork server {}", self.socket_path.display());
    }
}

const TAINTED_OFFSETS_FILE: &str = "tainted_offsets.json";
const TARGET_HOOK_FILE: &str = "target_hook.json";
const SNAPSHOT_TARGET_FILE: &str = "snapshot_target.json";
const TAINTED_BYTES_FILE: &str = "tainted_bytes.json";
const DELAYED_FORKSRV_SOCKET_FILE: &str = "delayed_forksrv_socket";
const PLACEMENT_FORKSRV_SOCKET_FILE: &str = "placement_forksrv_socket";
const DFSAN_SNAP_FORKSRV_SOCKET_FILE: &str = "dfsan_snap_forksrv_socket";
const XRAY_SNAP_FORKSRV_SOCKET_FILE: &str = "xray_snap_forksrv_socket";
const SOCKET_DISPATCH_PATH: &str = "socket_dispatch.txt";

const SUCCESS_EXIT_CODE: i32 = 42;
const FAILURE_EXIT_CODE: i32 = 24;

const TAINTED_OFFSETS_PATH_VARNAME: &str = "TRACER_TAINTED_OFFSETS_FILE";
const INPUT_PATH_VARNAME: &str = "TRACER_INPUT_FILE";
const OUTPUT_PATH_VARNAME: &str = "TRACER_OUTPUT_FILE";
const SNAPSHOT_TARGET_VARNAME: &str = "TRACER_SNAPSHOT_TARGET";
const TAINTS_VARNAME: &str = "XRAY_SNAPSHOT_TAINTS";
const ENABLED_VARNAME: &str = "TRACER_ENABLED";

type AnalysisInputs = (Vec<TagSeg>, u64);
type AnalysisOutputs = (TargetHookInfo, Vec<(AddressKind, usize)>);

pub struct DelayedForkServerFactory {
    base_dir: PathBuf,
    xray_maps: (XRayMap, XRayMap),

    tainted_offsets_path: PathBuf,
    target_hook_path: PathBuf,
    snapshot_target_path: PathBuf,
    tainted_bytes_path: PathBuf,
    forksrv_socket_dispatch_path: PathBuf,

    snapshot_placement_forksrv: ManuallyDrop<Forksrv>,
    dfsan_snapshot_forksrv: ManuallyDrop<Forksrv>,
    xray_snapshot_forksrv: ManuallyDrop<Forksrv>,

    dfsan_snapshot_binary_path: PathBuf,
    xray_snapshot_binary_path: PathBuf,
    uses_asan: bool,
    time_limit: Duration,

    serial_id: u64,

    analysis_cache: HashMap<AnalysisInputs, Option<AnalysisOutputs>>,
}

impl DelayedForkServerFactory {
    pub fn new(
        base_dir: impl AsRef<Path>,

        snapshot_placement_target: &(PathBuf, Vec<OsString>),
        dfsan_snapshot_target: &(PathBuf, Vec<OsString>),
        xray_snapshot_target: &(PathBuf, Vec<OsString>),
        env_vars: &HashMap<OsString, OsString>,

        input_file_path: impl AsRef<Path>,
        test_case_shm_id: i32,
        xray_maps: (XRayMap, XRayMap),

        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
    ) -> anyhow::Result<Self> {
        fs::create_dir(&base_dir)
            .context("Failed to create delayed fork server factory directory")?;
        let base_dir = base_dir.as_ref().canonicalize().unwrap();
        log::info!(
            "Setting up delayed fork server factory: {}",
            base_dir.display()
        );

        let tainted_offsets_path = base_dir.join(TAINTED_OFFSETS_FILE);
        let target_hook_path = base_dir.join(TARGET_HOOK_FILE);
        let snapshot_placement_forksrv_socket = base_dir.join(PLACEMENT_FORKSRV_SOCKET_FILE);
        let snapshot_placement_forksrv = Self::prepare_snapshot_placement_forksrv(
            snapshot_placement_forksrv_socket,
            &target_hook_path,
            snapshot_placement_target,
            env_vars,
            &input_file_path,
            fd,
            is_stdin,
            uses_asan,
            config::TIME_LIMIT_TRACK,
            config::MEM_LIMIT_TRACK,
            &tainted_offsets_path,
        )?;

        let snapshot_target_path = base_dir.join(SNAPSHOT_TARGET_FILE);
        let tainted_bytes_path = base_dir.join(TAINTED_BYTES_FILE);
        let dfsan_snapshot_forksrv_socket = base_dir.join(DFSAN_SNAP_FORKSRV_SOCKET_FILE);
        let dfsan_snapshot_forksrv = Self::prepare_dfsan_snapshot_forksrv(
            dfsan_snapshot_forksrv_socket,
            dfsan_snapshot_target,
            env_vars,
            &input_file_path,
            fd,
            is_stdin,
            uses_asan,
            config::TIME_LIMIT_TRACK,
            config::MEM_LIMIT_TRACK,
            &tainted_offsets_path,
            &snapshot_target_path,
            &tainted_bytes_path,
        )?;

        let forksrv_socket_dispatch_path = base_dir.join(SOCKET_DISPATCH_PATH);
        let xray_snapshot_forksrv_socket = base_dir.join(XRAY_SNAP_FORKSRV_SOCKET_FILE);
        Self::serialize_socket_dispatch_path(
            &forksrv_socket_dispatch_path,
            &xray_snapshot_forksrv_socket,
        )?;
        let xray_snapshot_forksrv = Self::prepare_xray_fork_server(
            &forksrv_socket_dispatch_path,
            &xray_snapshot_forksrv_socket,
            xray_snapshot_target,
            env_vars,
            test_case_shm_id,
            fd,
            is_stdin,
            uses_asan,
            time_limit,
            mem_limit,
            &snapshot_target_path,
            &tainted_bytes_path,
        )?;

        Ok(Self {
            base_dir,
            xray_maps,

            tainted_offsets_path,
            target_hook_path,
            snapshot_target_path,
            tainted_bytes_path,
            forksrv_socket_dispatch_path,

            snapshot_placement_forksrv: ManuallyDrop::new(snapshot_placement_forksrv),
            dfsan_snapshot_forksrv: ManuallyDrop::new(dfsan_snapshot_forksrv),
            xray_snapshot_forksrv: ManuallyDrop::new(xray_snapshot_forksrv),

            dfsan_snapshot_binary_path: dfsan_snapshot_target.0.canonicalize().unwrap(),
            xray_snapshot_binary_path: xray_snapshot_target.0.canonicalize().unwrap(),
            uses_asan,
            time_limit,

            serial_id: 0,

            analysis_cache: Default::default(),
        })
    }

    pub fn build(
        &mut self,
        tainted_ranges: &[TagSeg],
        test_case_id: u64,
    ) -> anyhow::Result<Option<(Forksrv, TargetHookInfo)>> {
        let new_forksrv_id = self.serial_id;
        self.serial_id += 1;

        let (target_hook_info, tainted_bytes) = if let Some(analysis_output) = self
            .analysis_cache
            .get(&(tainted_ranges.to_vec(), test_case_id))
        {
            if let Some((target_hook_info, tainted_bytes)) = analysis_output {
                (target_hook_info.clone(), tainted_bytes.to_vec())
            } else {
                log::debug!("Tainted offsets on cached failure: {:?}", tainted_ranges);
                return Ok(None);
            }
        } else {
            log::debug!("Snapshot analysis cache miss, taking new snapshot");

            self.serialize_tainted_offsets(tainted_ranges)?;
            let target_hook_info = self.run_snapshot_placement().map_err(|error| {
                log::warn!("Tainted offsets on failure: {:?}", tainted_ranges);
                self.analysis_cache
                    .insert((tainted_ranges.to_vec(), test_case_id), None);
                error
            })?;

            self.serialize_snapshot_target(&target_hook_info, &self.xray_maps.0)?;
            let tainted_bytes = self.run_dfsan_snapshot().map_err(|error| {
                log::warn!("Tainted offsets on failure: {:?}", tainted_ranges);
                log::warn!("Snapshot target on failure: {:?}", target_hook_info);
                self.analysis_cache
                    .insert((tainted_ranges.to_vec(), test_case_id), None);
                error
            })?;

            let (target_hook_info, tainted_bytes) = self
                .analysis_cache
                .entry((tainted_ranges.to_vec(), test_case_id))
                .or_insert(Some((target_hook_info, tainted_bytes)))
                .as_ref()
                .unwrap();

            log::debug!("New snapshot test case: {}", test_case_id);
            log::debug!("New snapshot tainted offsets: {:?}", tainted_ranges);
            log::debug!("New snapshot target: {:?}", target_hook_info);
            log::debug!("New snapshot tainted bytes: {:?}", tainted_bytes);

            (target_hook_info.clone(), tainted_bytes.to_vec())
        };

        // Reserialize snapshot target because XRay snapshot may use different IDs.
        self.serialize_snapshot_target(&target_hook_info, &self.xray_maps.1)?;

        self.serialize_tainted_bytes(&tainted_bytes)?;

        let delayed_forksrv_socket_path = self.base_dir.join(format!(
            "{}_{}",
            DELAYED_FORKSRV_SOCKET_FILE, new_forksrv_id
        ));
        Self::serialize_socket_dispatch_path(
            &self.forksrv_socket_dispatch_path,
            &delayed_forksrv_socket_path,
        )?;
        let new_forksrv = self
            .get_delayed_fork_server(&delayed_forksrv_socket_path)
            .map_err(|error| {
                log::warn!("Tainted offsets on failure: {:?}", tainted_ranges);
                log::warn!("Snapshot target on failure: {:?}", target_hook_info);
                log::warn!("Tainted bytes on failure: {:#?}", tainted_bytes);

                // Invalidate cache if the analysis succeded, but the snapshot cannot be used.
                self.analysis_cache
                    .insert((tainted_ranges.to_vec(), test_case_id), None);

                error
            })?;

        Ok(Some((new_forksrv, target_hook_info)))
    }

    fn prepare_snapshot_placement_forksrv(
        snapshot_placement_forksrv_socket: impl AsRef<Path>,
        target_hook_path: impl AsRef<Path>,
        snapshot_placement_target: &(PathBuf, Vec<OsString>),
        env_vars: &HashMap<OsString, OsString>,
        input_file_path: impl AsRef<Path>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
        tainted_offsets_path: impl AsRef<Path>,
    ) -> anyhow::Result<Forksrv> {
        let begin = Instant::now();

        let mut env_vars = env_vars.clone();
        env_vars.insert(OsString::from(ENABLED_VARNAME), true.to_string().into());
        env_vars.insert(
            OsString::from(INPUT_PATH_VARNAME),
            input_file_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(OUTPUT_PATH_VARNAME),
            target_hook_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(TAINTED_OFFSETS_PATH_VARNAME),
            tainted_offsets_path.as_ref().to_path_buf().into(),
        );

        let fork_server = Forksrv::new(
            snapshot_placement_forksrv_socket,
            snapshot_placement_target,
            &env_vars,
            fd,
            is_stdin,
            uses_asan,
            time_limit,
            mem_limit,
        )
        .context("Failed to setup snapshot placement fork server")?;

        log::debug!(
            "Snapshot placement fork server setup took: {:?}",
            begin.elapsed()
        );

        Ok(fork_server)
    }

    fn run_snapshot_placement(&mut self) -> Result<TargetHookInfo, anyhow::Error> {
        let begin = Instant::now();

        let exit_code = match self.snapshot_placement_forksrv.run()? {
            StatusType::Normal(exit_code) => exit_code,
            StatusType::Timeout => return Err(anyhow!("Snapshot placement timed out")),
            StatusType::Crash => return Err(anyhow!("Snapshot placement crashed")),
            _ => unreachable!(),
        };

        match exit_code {
            Some(SUCCESS_EXIT_CODE) | None => (),
            Some(FAILURE_EXIT_CODE) => {
                return Err(anyhow!("Could not determine snapshot position"))
            },
            exit_code => {
                return Err(anyhow!(
                    "Unknown snapshot placement exit code: {}",
                    exit_code.unwrap()
                ))
            },
        }

        let target_hook_info;
        {
            let target_hook_info_file = BufReader::new(
                File::open(&self.target_hook_path).context("Could not open target symbol file")?,
            );
            target_hook_info = serde_json::from_reader(target_hook_info_file)
                .context("Target hook info decoding failed")?;
        }
        fs::remove_file(&self.target_hook_path).unwrap();

        log::debug!("Snapshot placement took: {:?}", begin.elapsed());

        Ok(target_hook_info)
    }

    fn prepare_dfsan_snapshot_forksrv(
        dfsan_snapshot_forksrv_socket: impl AsRef<Path>,
        dfsan_snapshot_target: &(PathBuf, Vec<OsString>),
        env_vars: &HashMap<OsString, OsString>,
        input_file_path: impl AsRef<Path>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
        tainted_offsets_path: impl AsRef<Path>,
        snapshot_target_path: impl AsRef<Path>,
        tainted_bytes_path: impl AsRef<Path>,
    ) -> anyhow::Result<Forksrv> {
        let begin = Instant::now();

        let mut env_vars = env_vars.clone();
        env_vars.insert(OsString::from(ENABLED_VARNAME), true.to_string().into());
        env_vars.insert(
            OsString::from(INPUT_PATH_VARNAME),
            input_file_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(OUTPUT_PATH_VARNAME),
            tainted_bytes_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(TAINTED_OFFSETS_PATH_VARNAME),
            tainted_offsets_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(SNAPSHOT_TARGET_VARNAME),
            snapshot_target_path.as_ref().to_path_buf().into(),
        );

        let fork_server = Forksrv::new(
            dfsan_snapshot_forksrv_socket,
            dfsan_snapshot_target,
            &env_vars,
            fd,
            is_stdin,
            uses_asan,
            time_limit,
            mem_limit,
        )
        .context("Failed to setup DFSanSnapshot fork server")?;

        log::debug!(
            "DFSanSnapshot fork server setup took: {:?}",
            begin.elapsed()
        );

        Ok(fork_server)
    }

    fn run_dfsan_snapshot(&mut self) -> Result<Vec<(AddressKind, usize)>, anyhow::Error> {
        let begin = Instant::now();

        let exit_code = match self.dfsan_snapshot_forksrv.run()? {
            StatusType::Normal(exit_code) => exit_code,
            StatusType::Timeout => return Err(anyhow!("DFSan snapshot timed out")),
            StatusType::Crash => return Err(anyhow!("DFSan snapshot crashed")),
            _ => unreachable!(),
        };
        match exit_code {
            Some(SUCCESS_EXIT_CODE) | None => (),
            Some(FAILURE_EXIT_CODE) => {
                return Err(anyhow!("Could not determine snapshot tainted bytes"))
            },
            exit_code => {
                return Err(anyhow!(
                    "Unknown DFSan snapshot exit code: {}",
                    exit_code.unwrap()
                ));
            },
        }

        // If the path hint produced by the DFSan snapshot instrumentation
        // points to the binary itself, it needs to be updated to point to the
        // XRay snapshot binary.

        let mut tainted_bytes: Vec<(AddressKind, usize)>;
        {
            let mut tainted_bytes_file = BufReader::new(
                File::open(&self.tainted_bytes_path)
                    .context("Could not open tainted bytes JSON file")?,
            );
            tainted_bytes = serde_json::from_reader(&mut tainted_bytes_file)
                .context("Could not deserialize tainted bytes")?;
        }
        fs::remove_file(&self.tainted_bytes_path).unwrap();

        for (address_kind, _input_offset) in &mut tainted_bytes {
            match address_kind {
                AddressKind::Stack {
                    record_id: _,
                    location_idx: _,
                    location_offt: _,
                    stack_map_num_functions_hint: _,
                    stack_map_file_hint,
                } => {
                    let canonical_stack_map_file_hint =
                        stack_map_file_hint.canonicalize().with_context(|| {
                            format!(
                                "Could not canonicalize file hint: {}",
                                stack_map_file_hint.display()
                            )
                        })?;

                    if canonical_stack_map_file_hint == self.dfsan_snapshot_binary_path {
                        *stack_map_file_hint = self.xray_snapshot_binary_path.clone();
                    }
                },
                AddressKind::Static {
                    symbol: _,
                    symbol_idx: _,
                    offset: _,
                    binary_path,
                } => {
                    let canonical_binary_path = binary_path.canonicalize().with_context(|| {
                        format!(
                            "Could not canonicalize binary path: {}",
                            binary_path.display()
                        )
                    })?;

                    if canonical_binary_path == self.dfsan_snapshot_binary_path {
                        *binary_path = self.xray_snapshot_binary_path.clone();
                    }
                },
                _ => (),
            }
        }

        if log_enabled!(log::Level::Trace) {
            log::trace!("Tainted data in snapshot ({} bytes):", tainted_bytes.len());

            for tainted_byte in &tainted_bytes {
                log::trace!("{:?}", tainted_byte);
            }
        }

        log::debug!("DFSan snapshot took: {:?}", begin.elapsed());

        Ok(tainted_bytes)
    }

    fn prepare_xray_fork_server(
        forksrv_socket_dispatch_path: impl AsRef<Path>,
        xray_snapshot_forksrv_socket: impl AsRef<Path>,
        xray_snapshot_target: &(PathBuf, Vec<OsString>),
        env_vars: &HashMap<OsString, OsString>,
        test_case_shm_id: i32,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: Duration,
        mem_limit: u64,
        snapshot_target_path: impl AsRef<Path>,
        tainted_bytes_path: impl AsRef<Path>,
    ) -> Result<Forksrv, anyhow::Error> {
        let begin = Instant::now();

        let mut env_vars = env_vars.clone();
        env_vars.insert(
            OsString::from(TAINTS_VARNAME),
            tainted_bytes_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(
            OsString::from(SNAPSHOT_TARGET_VARNAME),
            snapshot_target_path.as_ref().to_path_buf().into(),
        );
        env_vars.insert(OsString::from(ENABLED_VARNAME), true.to_string().into());
        env_vars.insert(
            OsString::from(defs::TEST_CASE_SHM_ID_VARNAME),
            test_case_shm_id.to_string().into(),
        );

        let fork_server = Forksrv::new_with_client_callback(
            xray_snapshot_forksrv_socket,
            uses_asan,
            time_limit,
            || {
                // For this fork server, the path of the Unix socket to be
                // opened is written on a file whose path is, in turn, passed in
                // an environment variable.
                env_vars.insert(
                    OsString::from(defs::FORKSRV_SOCKET_PATH_VAR),
                    forksrv_socket_dispatch_path.as_ref().into(),
                );

                let (stdout_redirect, stderr_redirect) = if log::log_enabled!(log::Level::Info) {
                    if log::log_enabled!(log::Level::Trace) {
                        (Stdio::inherit(), Stdio::inherit())
                    } else {
                        (Stdio::null(), Stdio::inherit())
                    }
                } else {
                    (Stdio::null(), Stdio::null())
                };

                let process = Command::new(&xray_snapshot_target.0)
                    .args(&xray_snapshot_target.1)
                    .stdin(Stdio::null())
                    .envs(&env_vars)
                    .stdout(stdout_redirect)
                    .stderr(stderr_redirect)
                    .mem_limit(mem_limit)
                    .block_core_files()
                    .setsid()
                    .pipe_stdin(fd, is_stdin)
                    .spawn()
                    .context("Failed to spawn child.")?;

                Ok(Some(process))
            },
        )?;

        log::debug!("XRay fork server setup took: {:?}", begin.elapsed());

        Ok(fork_server)
    }

    fn get_delayed_fork_server(
        &mut self,
        delayed_forksrv_socket_path: impl AsRef<Path>,
    ) -> Result<Forksrv, anyhow::Error> {
        let begin = Instant::now();

        let delayed_fork_server = Forksrv::new_with_client_callback(
            delayed_forksrv_socket_path,
            self.uses_asan,
            self.time_limit,
            || {
                let child_pid = self.xray_snapshot_forksrv.spawn()?;
                log::debug!("New child with PID: {}", child_pid);
                Ok(None)
            },
        )
        .context("Could not prepare delayed fork server")?;

        log::debug!("Delayed fork server setup took: {:?}", begin.elapsed());

        Ok(delayed_fork_server)
    }

    fn serialize_tainted_offsets(&self, tainted_ranges: &[TagSeg]) -> anyhow::Result<()> {
        let begin = Instant::now();

        let mut tainted_offsets = Vec::with_capacity(tainted_ranges.len());
        for tainted_range in tainted_ranges {
            for tainted_offt in tainted_range.begin..tainted_range.end {
                tainted_offsets.push(tainted_offt as usize);
            }
        }
        tainted_offsets.sort_unstable();
        tainted_offsets.dedup();
        log::trace!("Tainted offsets: {:?}", tainted_offsets);

        let tainted_offsets_file = BufWriter::new(
            File::create(&self.tainted_offsets_path)
                .context("Could not create tainted offsets file")?,
        );
        serde_json::to_writer(tainted_offsets_file, &tainted_offsets)
            .context("Could not serialize offsets")?;

        log::debug!(
            "Serialization of tainted offsets took: {:?}",
            begin.elapsed()
        );

        Ok(())
    }

    fn serialize_snapshot_target(
        &self,
        target_hook_info: &TargetHookInfo,
        xray_map: &XRayMap,
    ) -> anyhow::Result<()> {
        let begin = Instant::now();

        let symbol_name = target_hook_info.symbol_name();
        let target_ids = xray_map
            .get(symbol_name)
            .with_context(|| format!("Could not find symbol in XRay map: {}", symbol_name))?;

        let snapshot_target_file = BufWriter::new(
            File::create(&self.snapshot_target_path)
                .context("Could not create snapshot target file")?,
        );

        #[derive(Serialize, Debug)]
        pub struct SnapshotTarget<'a> {
            target_ids: Vec<FunctionID>,
            target_kind: &'a str,
            hit_count: usize,
        }

        let snapshot_target = SnapshotTarget {
            target_ids: target_ids.iter().cloned().collect(),
            target_kind: target_hook_info.symbol_type(),
            hit_count: target_hook_info.hit_count(),
        };
        log::trace!("Snapshot target ({}): {:?}", symbol_name, snapshot_target);

        serde_json::to_writer(snapshot_target_file, &snapshot_target)
            .context("Could not serialize snapshot target")?;

        log::debug!("Snapshot target serialization took: {:?}", begin.elapsed());

        Ok(())
    }

    fn serialize_tainted_bytes(
        &self,
        tainted_bytes: &[(AddressKind, usize)],
    ) -> anyhow::Result<()> {
        let mut tainted_bytes_file = BufWriter::new(
            File::create(&self.tainted_bytes_path)
                .context("Could not open tainted bytes JSON file")?,
        );
        serde_json::to_writer(&mut tainted_bytes_file, &tainted_bytes)
            .context("Could not serialize tainted bytes")?;

        Ok(())
    }

    fn serialize_socket_dispatch_path(
        forksrv_socket_dispatch_path: impl AsRef<Path>,
        forksrv_socket_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let mut forksrv_socket_dispatch_file = BufWriter::new(
            File::create(forksrv_socket_dispatch_path)
                .context("Could not create snapshot target file")?,
        );

        writeln!(
            forksrv_socket_dispatch_file,
            "{}",
            forksrv_socket_path.as_ref().display()
        )?;

        Ok(())
    }

    pub fn take_analysis_cache(&mut self) -> HashMap<AnalysisInputs, Option<AnalysisOutputs>> {
        mem::take(&mut self.analysis_cache)
    }

    pub fn set_analysis_cache(
        &mut self,
        analysis_cache: HashMap<AnalysisInputs, Option<AnalysisOutputs>>,
    ) {
        self.analysis_cache = analysis_cache
    }
}

impl Drop for DelayedForkServerFactory {
    fn drop(&mut self) {
        // The fork servers need the directory that is eliminated on drop in
        // order to communicate to the related processes that they should exit.
        log::debug!("Dropping factory fork servers");
        unsafe {
            ManuallyDrop::drop(&mut self.xray_snapshot_forksrv);
            ManuallyDrop::drop(&mut self.dfsan_snapshot_forksrv);
            ManuallyDrop::drop(&mut self.snapshot_placement_forksrv);
        }

        log::debug!(
            "Removing delayed fork server factory folder: {}",
            self.base_dir.display()
        );
        fs::remove_dir_all(&self.base_dir).unwrap();
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Clone)]
pub struct TargetHookInfo {
    symbol_name: String,
    symbol_type: String,
    hit_count: usize,
}

impl TargetHookInfo {
    /// Get a reference to the target hook info's symbol name.
    fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Get a reference to the target hook info's symbol type.
    fn symbol_type(&self) -> &str {
        &self.symbol_type
    }

    /// Get a reference to the target hook info's hit count.
    fn hit_count(&self) -> usize {
        self.hit_count
    }
}

pub type AllocID = usize;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(tag = "type")]
pub enum AddressKind {
    Stack {
        record_id: u64,
        location_idx: usize,
        location_offt: usize,
        stack_map_num_functions_hint: usize,
        stack_map_file_hint: PathBuf,
    },
    Static {
        symbol: String,
        symbol_idx: usize,
        offset: usize,
        binary_path: PathBuf,
    },
    Heap {
        id: AllocID,
        size: usize,
        offset: usize,
    },
}
