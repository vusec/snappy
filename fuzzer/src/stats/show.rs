use super::ChartStats;
use crate::{branches::GlobalBranches, depot::Depot};
use angora_common::defs;
use hdrhistogram::{
    serialization::{Serializer, V2DeflateSerializer},
    Histogram,
};
use std::{
    fs::File,
    io::{prelude::*, BufWriter},
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard},
};

pub fn show_and_log_stats(
    log_file: &mut File,
    depot: &Arc<Depot>,
    gb: &Arc<GlobalBranches>,
    stats: &Arc<RwLock<ChartStats>>,
) {
    log::trace!("Update global statistics");
    stats.write().unwrap().sync_from_global(depot, gb);

    let stats_read = stats.read().unwrap();
    println!("{}", stats_read);

    log::trace!("Update log files");
    writeln!(log_file, "{}", stats_read.mini_log()).expect("Could not write minilog.");

    let output_dir = depot
        .dirs
        .inputs_dir
        .parent()
        .expect("Could not get parent directory.");
    write_chart_stat_file(output_dir, &stats_read);
    serialize_histograms(output_dir, &stats_read);
    serialize_snapshot_position_stats(output_dir, &stats_read);
}

fn write_chart_stat_file(output_dir: impl AsRef<Path>, stats: &RwLockReadGuard<ChartStats>) {
    let char_stat_file = BufWriter::new(
        File::create(output_dir.as_ref().join(defs::CHART_STAT_FILE))
            .expect("Could not create chart stat file."),
    );

    serde_json::to_writer(char_stat_file, &**stats).expect("Could not write stats file");
}

fn serialize_histograms(output_dir: impl AsRef<Path>, stats: &RwLockReadGuard<ChartStats>) {
    serialize_histogram(
        &output_dir,
        defs::EXECS_PER_SNAP_COND_HIST_FILE,
        stats.hist_execs_per_snap_cond(),
    );
    serialize_histogram(
        &output_dir,
        defs::EXECS_PER_SNAP_COND_DECAY_HIST_FILE,
        stats.hist_execs_per_snap_cond_decay(),
    );
    serialize_histogram(
        &output_dir,
        defs::EXECS_PER_SNAPSHOT_HIST_FILE,
        stats.hist_execs_per_snapshot(),
    );
    serialize_histogram(
        &output_dir,
        defs::DELAYED_EXECS_MICROS_HIST_FILE,
        stats.hist_delayed_execs_micros(),
    );
    serialize_histogram(
        &output_dir,
        defs::PLAIN_EXECS_MICROS_HIST_FILE,
        stats.hist_plain_execs_micros(),
    );
    serialize_histogram(
        &output_dir,
        defs::TRACK_MICROS_HIST_FILE,
        stats.hist_track_micros(),
    );
    serialize_histogram(
        &output_dir,
        defs::SNAPSHOT_MICROS_HIST_FILE,
        stats.hist_snapshot_micros(),
    );
}

fn serialize_histogram(output_dir: impl AsRef<Path>, hist_file_name: &str, hist: &Histogram<u64>) {
    let mut hist_file = BufWriter::new(
        File::create(output_dir.as_ref().join(hist_file_name))
            .expect("Could not open histogram file"),
    );

    V2DeflateSerializer::new()
        .serialize(hist, &mut hist_file)
        .expect("Could not serialize histogram");
}

fn serialize_snapshot_position_stats(
    output_dir: impl AsRef<Path>,
    stats: &RwLockReadGuard<ChartStats>,
) {
    let pos_stats_file = BufWriter::new(
        File::create(output_dir.as_ref().join(defs::SNAPSHOT_POSITION_STATS_FILE))
            .expect("Could not open position stats file"),
    );

    let position_stats_vec = stats.snapshot_position_stats().iter().collect::<Vec<_>>();
    serde_json::to_writer(pos_stats_file, &position_stats_vec)
        .expect("Could not serialize position map");
}
