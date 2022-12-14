use crate::stats::*;
use angora_common::defs;
use chrono::prelude::Local;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{self, Duration},
};
use yaml_rust::{Yaml, YamlLoader};

use crate::{bind_cpu, branches, check_dep, command, depot, executor, fuzz_loop, stats};
use anyhow::{anyhow, Context, Result};
use ctrlc;
use libc;
use pretty_env_logger;

pub fn fuzz_main(
    mode: &str,
    in_dir: &str,
    out_dir: &str,
    track_target: &str,
    snapshot_placement_bin_path: &str,
    dfsan_snapshot_bin_path: &str,
    xray_snapshot_bin_path: &str,
    pargs: Vec<String>,
    num_jobs: usize,
    mem_limit: u64,
    time_limit: u64,
    search_method: &str,
    sync_afl: bool,
    enable_afl: bool,
    enable_exploitation: bool,
    deterministic_seed: Option<u64>,
    ignore_snapshot_threshold: bool,
) {
    pretty_env_logger::init();

    let (seeds_dir, angora_out_dir) = initialize_directories(in_dir, out_dir, sync_afl);
    let command_option = command::CommandOpt::new(
        mode,
        track_target,
        snapshot_placement_bin_path,
        dfsan_snapshot_bin_path,
        xray_snapshot_bin_path,
        pargs,
        &angora_out_dir,
        search_method,
        mem_limit,
        Duration::from_secs(time_limit),
        enable_afl,
        enable_exploitation,
        deterministic_seed,
        ignore_snapshot_threshold,
    );
    log::info!("{:#?}", command_option);

    check_dep::check_dep(in_dir, out_dir, &command_option);

    let dfsan_snapshot_xray_map = parse_xray_map(&command_option.dfsan_snapshot_target.0)
        .expect("Parsing DFSan snapshot binary failed");
    let xray_snapshot_xray_map = parse_xray_map(&command_option.xray_snapshot_target.0)
        .expect("Parsing XRay snapshot binary failed");

    let depot = Arc::new(depot::Depot::new(seeds_dir, &angora_out_dir));
    log::info!("{:#?}", depot.dirs);

    let stats = Arc::new(RwLock::new(stats::ChartStats::new()));
    let global_branches = Arc::new(branches::GlobalBranches::new());
    let fuzzer_stats = create_stats_file_and_write_pid(&angora_out_dir);
    let running = Arc::new(AtomicBool::new(true));
    set_sigint_handler(running.clone());

    log::trace!("Initializing sync executor");
    let mut executor = executor::Executor::new(
        command_option.specify(0),
        global_branches.clone(),
        depot.clone(),
        stats.clone(),
        (
            dfsan_snapshot_xray_map.clone(),
            xray_snapshot_xray_map.clone(),
        ),
    );

    log::trace!("Processing seed test cases");
    depot::sync_depot(&mut executor, running.clone(), &depot.dirs.seeds_dir);

    if depot.empty() {
        error!("Failed to find any branches during dry run.");
        error!("Please ensure that the binary has been instrumented and/or input directory is populated.");
        error!(
            "Please ensure that seed directory - {:?} has any file.",
            depot.dirs.seeds_dir
        );
        panic!();
    }

    let (handles, fuzz_thread_count) = init_cpus_and_run_fuzzing_threads(
        num_jobs,
        &running,
        &command_option,
        &global_branches,
        &depot,
        &stats,
        (dfsan_snapshot_xray_map, xray_snapshot_xray_map),
    );

    let log_file = match fs::File::create(angora_out_dir.join(defs::ANGORA_LOG_FILE)) {
        Ok(a) => a,
        Err(e) => {
            error!("FATAL: Could not create log file: {:?}", e);
            panic!();
        },
    };
    main_thread_sync_and_log(
        log_file,
        out_dir,
        sync_afl,
        running.clone(),
        &mut executor,
        &depot,
        &global_branches,
        &stats,
        fuzz_thread_count,
    );

    for handle in handles {
        if handle.join().is_err() {
            error!("Error happened in fuzzing thread!");
        }
    }

    match fs::remove_file(&fuzzer_stats) {
        Ok(_) => (),
        Err(e) => warn!("Could not remove fuzzer stats file: {:?}", e),
    };
}

fn initialize_directories(in_dir: &str, out_dir: &str, sync_afl: bool) -> (PathBuf, PathBuf) {
    let angora_out_dir = if sync_afl {
        gen_path_afl(out_dir)
    } else {
        PathBuf::from(out_dir)
    };

    let restart = in_dir == "-";
    if !restart {
        fs::create_dir(&angora_out_dir).expect("Output directory already exists!");
    }

    let out_dir = &angora_out_dir;
    let seeds_dir = if restart {
        let orig_out_dir = out_dir.with_extension(Local::now().to_rfc3339());
        fs::rename(&out_dir, orig_out_dir.clone()).unwrap();
        fs::create_dir(&out_dir).unwrap();
        PathBuf::from(orig_out_dir).join(defs::INPUTS_DIR)
    } else {
        PathBuf::from(in_dir)
    };

    (seeds_dir, angora_out_dir)
}

fn gen_path_afl(out_dir: &str) -> PathBuf {
    let base_path = PathBuf::from(out_dir);
    let create_dir_result = fs::create_dir(&base_path);
    if create_dir_result.is_err() {
        warn!("Shared output directory already exists: {:?}", base_path);
    }
    base_path.join(defs::ANGORA_DIR_NAME)
}

fn set_sigint_handler(r: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        warn!("Ending Fuzzing.");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting SIGINT handler!");
}

fn create_stats_file_and_write_pid(angora_out_dir: &PathBuf) -> PathBuf {
    // To be compatible with AFL.
    let fuzzer_stats = angora_out_dir.join("fuzzer_stats");
    let pid = unsafe { libc::getpid() as usize };
    let mut buffer = match fs::File::create(&fuzzer_stats) {
        Ok(a) => a,
        Err(e) => {
            error!("Could not create stats file: {:?}", e);
            panic!();
        },
    };
    write!(buffer, "fuzzer_pid : {}", pid).expect("Could not write to stats file");
    fuzzer_stats
}

fn init_cpus_and_run_fuzzing_threads(
    num_jobs: usize,
    running: &Arc<AtomicBool>,
    command_option: &command::CommandOpt,
    global_branches: &Arc<branches::GlobalBranches>,
    depot: &Arc<depot::Depot>,
    stats: &Arc<RwLock<stats::ChartStats>>,
    xray_maps: (XRayMap, XRayMap),
) -> (Vec<thread::JoinHandle<()>>, Arc<AtomicUsize>) {
    let free_cpus = bind_cpu::find_free_cpus(num_jobs);
    let bind_cpus = if free_cpus.len() < num_jobs {
        log::warn!("The number of free cpus is less than the number of jobs. Will not bind any thread to any cpu.");
        false
    } else {
        true
    };

    let fuzz_thread_count = Arc::new(AtomicUsize::new(0));
    let mut fuzz_thread_handles = Vec::with_capacity(num_jobs);
    for thread_id in 0..num_jobs {
        let running = Arc::clone(&running);
        let depot = Arc::clone(&depot);
        let global_branches = Arc::clone(&global_branches);
        let stats = Arc::clone(&stats);
        let fuzz_thread_count = Arc::clone(&fuzz_thread_count);
        let xray_maps = xray_maps.clone();

        let command_option = command_option.specify(thread_id + 1);
        let cid = if bind_cpus { free_cpus[thread_id] } else { 0 };
        let mut rng = if let Some(seed) = command_option.deterministic_seed {
            let thread_seed = seed + thread_id as u64;
            log::info!("Starting thread with seed: {}", thread_seed);
            ChaCha8Rng::seed_from_u64(thread_seed)
        } else {
            log::info!("Starting thread with seed from entropy");
            ChaCha8Rng::from_entropy()
        };

        let handle = thread::spawn(move || {
            fuzz_thread_count.fetch_add(1, Ordering::SeqCst);

            if bind_cpus {
                bind_cpu::bind_thread_to_cpu_core(cid);
            }

            fuzz_loop::fuzz_loop(
                running,
                command_option,
                depot,
                global_branches,
                stats,
                &mut rng,
                xray_maps,
            );

            fuzz_thread_count.fetch_sub(1, Ordering::SeqCst);
        });

        fuzz_thread_handles.push(handle);
    }

    (fuzz_thread_handles, fuzz_thread_count)
}

fn main_thread_sync_and_log(
    mut log_file: fs::File,
    out_dir: &str,
    sync_afl: bool,
    running: Arc<AtomicBool>,
    executor: &mut executor::Executor,
    depot: &Arc<depot::Depot>,
    global_branches: &Arc<branches::GlobalBranches>,
    stats: &Arc<RwLock<stats::ChartStats>>,
    fuzz_thread_count: Arc<AtomicUsize>,
) {
    let mut last_explore_num = stats.read().unwrap().get_explore_num();
    let sync_dir = Path::new(out_dir);
    let mut synced_ids = HashMap::new();
    if sync_afl {
        depot::sync_afl(executor, running.clone(), sync_dir, &mut synced_ids);
    }
    let mut sync_counter = 1;

    writeln!(log_file, "{}", stats.read().unwrap().mini_log_header())
        .expect("Failed to write log file header");
    show_and_log_stats(&mut log_file, depot, global_branches, stats);
    while running.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::from_secs(5));
        sync_counter -= 1;
        if sync_afl && sync_counter <= 0 {
            depot::sync_afl(executor, running.clone(), sync_dir, &mut synced_ids);
            sync_counter = 12;
        }

        show_and_log_stats(&mut log_file, depot, global_branches, stats);

        if fuzz_thread_count.load(Ordering::SeqCst) == 0 {
            let s = stats.read().unwrap();
            let cur_explore_num = s.get_explore_num();
            if cur_explore_num == 0 {
                log::warn!("No constraint could be found in the seeds! Please make sure that the seed test cases are valid, that the program is ran correctly and that the functions that read tainted data have been marked as taint sources.");
                break;
            } else {
                if cur_explore_num == last_explore_num {
                    log::info!("Solved all constraints!");
                    break;
                }
                last_explore_num = cur_explore_num;
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum XRayHookKind {
    Entry,
    Exit,
}

impl FromStr for XRayHookKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ENTRY" => Ok(Self::Entry),
            "EXIT" => Ok(Self::Exit),
            _ => Err(anyhow!("Malformed kind entry")),
        }
    }
}

pub type FunctionID = i32;
pub type XRayMap = HashMap<String, BTreeSet<FunctionID>>;

pub fn parse_xray_map(binary_path: impl AsRef<Path>) -> Result<XRayMap> {
    let xray_map = Command::new("llvm-xray")
        .arg("extract")
        .arg("--symbolize")
        .arg("--no-demangle")
        .arg(binary_path.as_ref())
        .output()
        .with_context(|| {
            format!(
                "Failed to execute llvm-xray on: {}",
                binary_path.as_ref().display()
            )
        })?;
    let xray_map =
        std::str::from_utf8(&xray_map.stdout).context("Failed to parse output as UTF-8")?;
    let xray_map = YamlLoader::load_from_str(xray_map).with_context(|| {
        format!(
            "Failed to parse XRay YAML map from: {}",
            binary_path.as_ref().display(),
        )
    })?;
    let xray_map = &xray_map[0];

    let mut parsed_xray_map: XRayMap = HashMap::new();
    for xray_hook in xray_map.as_vec().ok_or(anyhow!("Malformed YAML"))? {
        let xray_hook = xray_hook.as_hash().ok_or(anyhow!("Malformed YAML"))?;
        let id = xray_hook[&Yaml::from_str("id")]
            .as_i64()
            .ok_or(anyhow!("Malformed id field"))?;

        let mut function_name = xray_hook[&Yaml::from_str("function-name")]
            .as_str()
            .ok_or(anyhow!("Malformed function-name field"))?
            .to_string();

        // dfsw$ should not be stripped because it identifies functions that
        // simply wrap the plain symbol. Stripping it would cause a double
        // count.
        if let Some(stripped_function_name) = function_name.strip_prefix("dfs$") {
            function_name = stripped_function_name.to_string();
        }

        parsed_xray_map
            .entry(function_name)
            .or_default()
            .insert(id as FunctionID);
    }

    Ok(parsed_xray_map)
}
