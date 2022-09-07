use angora_common::tag::TagSeg;
use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use angora::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::CondStmt, depot::Depot,
    executor::Executor, fuzz_main::parse_xray_map, stats::ChartStats,
};

const ANGORA_FAST_VAR: &str = "BENCH_ANGORA_FAST";
const ANGORA_TRACK_VAR: &str = "BENCH_ANGORA_TRACK";
const SNAPSHOT_PLACEMENT_VAR: &str = "BENCH_SNAPSHOT_PLACEMENT";
const DFSAN_SNAPSHOT_VAR: &str = "BENCH_DFSAN_SNAPSHOT";
const XRAY_SNAPSHOT_VAR: &str = "BENCH_XRAY_SNAPSHOT";

fn construct_bench_opt(output_dir: &Path) -> CommandOpt {
    let angora_fast_path = env::var(ANGORA_FAST_VAR).unwrap();
    let angora_track_path = env::var(ANGORA_TRACK_VAR).unwrap();
    let snapshot_placement_path = env::var(SNAPSHOT_PLACEMENT_VAR).unwrap();
    let dfsan_snapshot_path = env::var(DFSAN_SNAPSHOT_VAR).unwrap();
    let xray_snapshot_path = env::var(XRAY_SNAPSHOT_VAR).unwrap();

    let fast_cmdline = vec![angora_fast_path, String::from("@@")];

    CommandOpt::new(
        "llvm",
        &angora_track_path,
        &snapshot_placement_path,
        &dfsan_snapshot_path,
        &xray_snapshot_path,
        fast_cmdline,
        output_dir,
        "does_not_matter", // Unused
        angora_common::config::MEM_LIMIT,
        Duration::from_secs(angora_common::config::TIME_LIMIT),
        false, // Unused
        false, // Unused
        None,  // Unused
    )
}

fn construct_executor(cmd: CommandOpt, output_dir: &Path) -> Executor {
    let global_branches = Arc::new(GlobalBranches::new());
    let depot = Arc::new(Depot::new(PathBuf::from("/non/existent"), output_dir)); // Unused
    let global_stats = Arc::new(RwLock::new(ChartStats::new())); // Unused

    let dfsan_snapshot_xray_map =
        parse_xray_map(&cmd.dfsan_snapshot_target.0).expect("Parsing DFSan snapshot binary failed");
    let xray_snapshot_xray_map =
        parse_xray_map(&cmd.xray_snapshot_target.0).expect("Parsing XRay snapshot binary failed");

    Executor::new(
        cmd.clone(),
        global_branches,
        depot,
        global_stats,
        (dfsan_snapshot_xray_map, xray_snapshot_xray_map),
    )
}

pub fn compare_forkservers(c: &mut Criterion) {
    pretty_env_logger::try_init().ok();

    let tmp_output_dir = tempfile::tempdir().unwrap();
    let cmd = construct_bench_opt(tmp_output_dir.path());
    let mut executor = construct_executor(cmd.specify(0), tmp_output_dir.path());

    let test_case = "flag".as_bytes().to_vec();
    let mut cond = CondStmt::new();
    cond.offsets.push(TagSeg {
        sign: false,
        begin: 0,
        end: test_case.len() as u32,
    });

    let mut group = c.benchmark_group("forkservers");

    group.bench_function("plain", |b| b.iter(|| executor.run_sync(&test_case)));

    executor.start_delayed_fork_server(&test_case, &cond);
    group.bench_function("delayed", |b| b.iter(|| executor.run_sync(&test_case)));
    executor.stop_delayed_fork_server();

    group.finish();
}

pub fn delayed_forksrv_setup_teardown_benchmark(c: &mut Criterion) {
    pretty_env_logger::try_init().ok();

    let tmp_output_dir = tempfile::tempdir().unwrap();
    let cmd = construct_bench_opt(tmp_output_dir.path());
    let mut executor = construct_executor(cmd.specify(0), tmp_output_dir.path());

    let test_case = "flag".as_bytes().to_vec();
    let mut cond = CondStmt::new();
    cond.offsets.push(TagSeg {
        sign: false,
        begin: 0,
        end: test_case.len() as u32,
    });

    c.bench_function("delayed_forksrv_setup_teardown", |b| {
        b.iter(|| {
            executor.start_delayed_fork_server(&test_case, &cond);
            executor.stop_delayed_fork_server();
        })
    });
}

criterion_group!(
    benches,
    compare_forkservers,
    delayed_forksrv_setup_teardown_benchmark
);
criterion_main!(benches);
