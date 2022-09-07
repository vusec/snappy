use angora::{
    branches::{self, BranchBuf},
    executor::{SetLimit, StatusType},
};
use angora_common::defs;
use anyhow::Context;
use clap::{App, Arg};
use indicatif::ProgressBar;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let config = parse_args().context("Invalid arguments")?;

    let global_coverage_map = Arc::new(branches::GlobalBranches::new());
    let mut execution_coverage_map = branches::Branches::new(Arc::clone(&global_coverage_map));

    let mut env_vars = HashMap::new();
    env_vars.insert(
        OsString::from(defs::BRANCHES_SHM_ENV_VAR),
        execution_coverage_map.get_id().to_string().into(),
    );

    println!("Looking for test cases in: {}", config.queue_dir.display());

    let mut test_cases = Vec::new();
    for entry in fs::read_dir(&config.queue_dir).context("Could not iterate on queue dir")? {
        let entry = entry.context("Could not get directory entry")?.path();
        if !entry.is_file()
            || !entry
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("id:")
        {
            continue;
        }

        test_cases.push(entry);
    }

    // Sort test cases to preserve the order in which they were first produced.
    test_cases.sort();

    println!("{} test cases found.", test_cases.len());

    let analysis_start = Instant::now();

    let mut non_zero_counts = Vec::with_capacity(test_cases.len());
    let mut densities = Vec::with_capacity(test_cases.len());

    let mut count_no_new_path = 0;
    let progress_bar = ProgressBar::new(test_cases.len() as u64);
    for test_case in test_cases.iter() {
        progress_bar.inc(1);

        execution_coverage_map.clear_trace();
        let status = run_fast_binary_with_test_case(&config, &env_vars, test_case);
        if !matches!(status, StatusType::Normal(_)) {
            progress_bar.println(format!("Crash for test case: {}", test_case.display()));
            continue;
        }

        let non_zero_count = count_non_zero(execution_coverage_map.trace());
        non_zero_counts.push(non_zero_count);
        densities.push(non_zero_count as f64 / execution_coverage_map.trace().len() as f64);

        let (new_path, _new_cov, _total_edges) = execution_coverage_map.has_new(status, false);
        if !new_path {
            count_no_new_path += 1;
        }
    }
    progress_bar.finish();

    println!("Analysis took: {:?}", analysis_start.elapsed());

    println!(
        "Test cases with no new path: {} ({:.2}%)",
        count_no_new_path,
        count_no_new_path as f64 / test_cases.len() as f64 * 100f64
    );

    let mean_density: f64 = densities.iter().sum::<f64>() / test_cases.len() as f64;
    println!("Mean shared map density is: {}", mean_density);

    println!(
        "Global map density is: {}",
        global_coverage_map.get_density()
    );

    write_output_data(&config, &non_zero_counts)?;

    Ok(())
}

#[derive(Debug)]
struct Config {
    fast_binary: PathBuf,
    fast_args: Vec<OsString>,
    queue_dir: PathBuf,
    output_path: PathBuf,
}

fn parse_args() -> anyhow::Result<Config> {
    let matches = App::new("map_stats")
        .arg(
            Arg::with_name("queue_dir")
                .short("q")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output_path")
                .short("o")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("FAST_CMDLINE")
                .required(true)
                .multiple(true)
                .allow_hyphen_values(true)
                .last(true),
        )
        .get_matches();

    let queue_dir = PathBuf::from(matches.value_of("queue_dir").unwrap());
    let output_path = PathBuf::from(matches.value_of("output_path").unwrap());

    let mut fast_cmdline = matches.values_of_os("FAST_CMDLINE").unwrap();
    let fast_binary = PathBuf::from(fast_cmdline.next().context("No binary path provided")?);
    let fast_args = fast_cmdline.map(|x| x.to_owned()).collect::<Vec<_>>();

    Ok(Config {
        fast_binary,
        fast_args,
        queue_dir,
        output_path,
    })
}

const TIME_LIMIT: Duration = Duration::from_secs(angora_common::config::TIME_LIMIT);

fn run_fast_binary_with_test_case(
    config: &Config,
    env_vars: &HashMap<OsString, OsString>,
    test_case: &Path,
) -> StatusType {
    let mut fast_args = config.fast_args.clone();
    for elem in &mut fast_args {
        if *elem == OsStr::new("@@") {
            *elem = test_case.to_owned().into_os_string();
        }
    }

    let (stdout_redirect, stderr_redirect) = if log::log_enabled!(log::Level::Info) {
        if log::log_enabled!(log::Level::Trace) {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::inherit())
        }
    } else {
        (Stdio::null(), Stdio::null())
    };

    let mut child = Command::new(&config.fast_binary)
        .args(fast_args)
        .stdin(Stdio::null())
        .env_clear()
        .envs(env_vars)
        .stdout(stdout_redirect)
        .stderr(stderr_redirect)
        .mem_limit(angora_common::config::MEM_LIMIT)
        .block_core_files()
        .setsid()
        .spawn()
        .expect("Could not run target");

    match child.wait_timeout(TIME_LIMIT).unwrap() {
        Some(status) => {
            if let Some(status_code) = status.code() {
                StatusType::Normal(Some(status_code))
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
    }
}

fn count_non_zero(coverage_map: &BranchBuf) -> usize {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            unsafe { count_non_zero_avx2(coverage_map) }
        } else {
            count_non_zero_plain(coverage_map)
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        count_non_zero_plain(coverage_map);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn count_non_zero_avx2(coverage_map: &BranchBuf) -> usize {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__m256i, _mm256_cmpeq_epi8, _mm256_movemask_epi8, _mm256_setzero_si256};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{
        __m256i, _mm256_cmpeq_epi8, _mm256_movemask_epi8, _mm256_setzero_si256,
    };
    use std::{mem, slice};

    let zeroes = _mm256_setzero_si256();

    let coverage_map_words_avx2 = slice::from_raw_parts(
        coverage_map.as_ptr().cast::<__m256i>(),
        coverage_map.len() / mem::size_of::<__m256i>(),
    );

    let mut non_zero_bytes_count = 0;

    for &current_word_avx2 in coverage_map_words_avx2 {
        let cmp_zero_res = _mm256_cmpeq_epi8(current_word_avx2, zeroes);
        let cmp_zero_mask = _mm256_movemask_epi8(cmp_zero_res);
        if cmp_zero_mask == -1 {
            // All bytes in the current AVX2 word are zero.
            continue;
        }

        for bit_idx in 0..i32::BITS {
            if cmp_zero_mask & (1 << bit_idx) == 0 {
                non_zero_bytes_count += 1;
            }
        }
    }

    non_zero_bytes_count
}

fn count_non_zero_plain(coverage_map: &BranchBuf) -> usize {
    let mut non_zero_bytes_count = 0usize;

    for byte in coverage_map {
        if *byte > 0 {
            non_zero_bytes_count += 1;
        }
    }

    non_zero_bytes_count
}

fn write_output_data(config: &Config, non_zero_counts: &[usize]) -> anyhow::Result<()> {
    let mut writer =
        csv::Writer::from_path(&config.output_path).context("Could not open output file")?;

    writer
        .write_record(&["non_zero_counts"])
        .context("Could not write to output file")?;
    for non_zero_count in non_zero_counts {
        writer
            .write_record(&[non_zero_count.to_string()])
            .context("Could not write to output file")?;
    }

    Ok(())
}
