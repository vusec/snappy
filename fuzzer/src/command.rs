use crate::{check_dep, search, tmpfs};
use angora_common::defs;
use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

static TMP_DIR: &str = "tmp";
static INPUT_FILE: &str = "cur_input";
static FORKSRV_SOCKET_FILE: &str = "forksrv_socket";
const DELAYED_FORKSRV_TMP_DIR: &str = "delayed_forksrv";
static TRACK_FILE: &str = "track";
static PIN_ROOT_VAR: &str = "PIN_ROOT";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstrumentationMode {
    LLVM,
    Pin,
}

impl InstrumentationMode {
    pub fn from(mode: &str) -> Self {
        match mode {
            "llvm" => InstrumentationMode::LLVM,
            "pin" => InstrumentationMode::Pin,
            _ => unreachable!(),
        }
    }

    pub fn is_pin_mode(&self) -> bool {
        self == &InstrumentationMode::Pin
    }
}

#[derive(Debug, Clone)]
pub struct CommandOpt {
    pub mode: InstrumentationMode,
    pub id: usize,
    pub main: (PathBuf, Vec<OsString>),
    pub track: (PathBuf, Vec<OsString>),
    pub snapshot_placement_target: (PathBuf, Vec<OsString>),
    pub dfsan_snapshot_target: (PathBuf, Vec<OsString>),
    pub xray_snapshot_target: (PathBuf, Vec<OsString>),
    pub tmp_dir: PathBuf,
    pub out_file: PathBuf,
    pub forksrv_socket_path: PathBuf,
    pub delayed_forksrv_tmp_dir: PathBuf,
    pub track_path: PathBuf,
    pub is_stdin: bool,
    pub search_method: search::SearchMethod,
    pub mem_limit: u64,
    pub time_limit: Duration,
    pub is_raw: bool,
    pub uses_asan: bool,
    pub enable_afl: bool,
    pub enable_exploitation: bool,
    pub deterministic_seed: Option<u64>,
    pub ignore_snapshot_threshold: bool,
}

impl CommandOpt {
    pub fn new(
        mode: &str,
        track_target: &str,
        snapshot_placement_bin_path: &str,
        dfsan_snapshot_bin_path: &str,
        xray_snapshot_bin_path: &str,
        pargs: Vec<String>,
        out_dir: &Path,
        search_method: &str,
        mut mem_limit: u64,
        time_limit: Duration,
        enable_afl: bool,
        enable_exploitation: bool,
        deterministic_seed: Option<u64>,
        ignore_snapshot_threshold: bool,
    ) -> Self {
        let mode = InstrumentationMode::from(mode);

        let tmp_dir = out_dir.join(TMP_DIR);
        tmpfs::create_tmpfs_dir(&tmp_dir);

        let out_file = tmp_dir.join(INPUT_FILE);
        let forksrv_socket_path = tmp_dir.join(FORKSRV_SOCKET_FILE);
        let delayed_forksrv_tmp_dir = tmp_dir.join(DELAYED_FORKSRV_TMP_DIR);

        let track_path = tmp_dir.join(TRACK_FILE);

        let has_input_arg = pargs.contains(&"@@".to_string());

        assert_ne!(
            track_target, "-",
            "You should set track target with -t PROM in LLVM mode!"
        );

        let mut tmp_args = pargs.clone();
        let main_bin = tmp_args[0].clone();
        let main_args: Vec<OsString> = tmp_args.drain(1..).map(|arg| arg.into()).collect();
        let uses_asan = check_dep::check_asan(&main_bin);
        if uses_asan && mem_limit != 0 {
            warn!("The program compiled with ASAN, set MEM_LIMIT to 0 (unlimited)");
            mem_limit = 0;
        }

        let track_bin;
        let mut track_args = Vec::<OsString>::new();
        if mode.is_pin_mode() {
            let project_bin_dir =
                env::var(defs::ANGORA_BIN_DIR).expect("Please set ANGORA_PROJ_DIR");

            let pin_root =
                env::var(PIN_ROOT_VAR).expect("You should set the environment of PIN_ROOT!");
            let pin_bin = format!("{}/{}", pin_root, "pin");
            track_bin = pin_bin.to_string();
            let pin_tool = Path::new(&project_bin_dir).join("lib").join("pin_track.so");

            track_args.push(OsString::from("-t"));
            track_args.push(pin_tool.into_os_string());
            track_args.push(OsString::from("--"));
            track_args.push(OsString::from(track_target));
            track_args.extend(main_args.clone());
        } else {
            track_bin = track_target.to_string();
            track_args = main_args.clone();
        }

        Self {
            mode,
            id: 0,
            main: (main_bin.into(), main_args.clone()),
            track: (track_bin.into(), track_args),
            snapshot_placement_target: (
                snapshot_placement_bin_path.parse().unwrap(),
                main_args.clone(),
            ),
            dfsan_snapshot_target: (dfsan_snapshot_bin_path.parse().unwrap(), main_args.clone()),
            xray_snapshot_target: (xray_snapshot_bin_path.parse().unwrap(), main_args.clone()),
            tmp_dir,
            out_file,
            forksrv_socket_path,
            delayed_forksrv_tmp_dir,
            track_path,
            is_stdin: !has_input_arg,
            search_method: search::parse_search_method(search_method),
            mem_limit,
            time_limit,
            uses_asan,
            is_raw: true,
            enable_afl,
            enable_exploitation,
            deterministic_seed,
            ignore_snapshot_threshold,
        }
    }

    pub fn specify(&self, id: usize) -> Self {
        let mut cmd_opt = self.clone();
        let new_file = self.tmp_dir.join(format!("{}_{}", INPUT_FILE, id));
        let new_forksrv_socket_path = self.tmp_dir.join(format!("{}_{}", FORKSRV_SOCKET_FILE, id));
        let new_delayed_forksrv_tmp_dir = self
            .tmp_dir
            .join(format!("{}_{}", DELAYED_FORKSRV_TMP_DIR, id));
        let new_track_path = self.tmp_dir.join(format!("{}_{}", TRACK_FILE, id));
        if !self.is_stdin {
            for arg in &mut cmd_opt.main.1 {
                if arg == "@@" {
                    *arg = new_file.clone().into_os_string();
                }
            }
            for arg in &mut cmd_opt.track.1 {
                if arg == "@@" {
                    *arg = new_file.clone().into_os_string();
                }
            }
            for arg in &mut cmd_opt.snapshot_placement_target.1 {
                if arg == "@@" {
                    *arg = new_file.clone().into_os_string();
                }
            }
            for arg in &mut cmd_opt.dfsan_snapshot_target.1 {
                if arg == "@@" {
                    *arg = new_file.clone().into_os_string();
                }
            }
            for arg in &mut cmd_opt.xray_snapshot_target.1 {
                if arg == "@@" {
                    *arg = new_file.clone().into_os_string();
                }
            }
        }
        cmd_opt.id = id;
        cmd_opt.out_file = new_file.to_owned();
        cmd_opt.forksrv_socket_path = new_forksrv_socket_path;
        cmd_opt.delayed_forksrv_tmp_dir = new_delayed_forksrv_tmp_dir;
        cmd_opt.track_path = new_track_path;
        cmd_opt.is_raw = false;
        cmd_opt
    }
}

impl Drop for CommandOpt {
    fn drop(&mut self) {
        if self.is_raw {
            tmpfs::clear_tmpfs_dir(&self.tmp_dir);
        }
    }
}
