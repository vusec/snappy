use super::ChartStats;
use crate::{branches::GlobalBranches, depot::Depot};
use angora_common::defs;
use std::{
    fs::File,
    io::{BufWriter, Write},
    sync::{Arc, RwLock, RwLockReadGuard},
};

pub fn show_and_log_stats(
    log_file: &mut File,
    depot: &Arc<Depot>,
    gb: &Arc<GlobalBranches>,
    stats: &Arc<RwLock<ChartStats>>,
) {
    {
        stats
            .write()
            .expect("Could not write stats.")
            .sync_from_global(depot, gb);
    }

    let stats_read = stats.read().expect("Could not read from stats.");
    println!("{}", *stats_read);
    writeln!(log_file, "{}", stats_read.mini_log()).expect("Could not write minilog.");
    write_chart_stat_file(depot, &stats_read)
}

fn write_chart_stat_file(depot: &Arc<Depot>, stats: &RwLockReadGuard<ChartStats>) {
    let output_dir = depot
        .dirs
        .inputs_dir
        .parent()
        .expect("Could not get parent directory.");

    let char_stat_file = BufWriter::new(
        File::create(output_dir.join(defs::CHART_STAT_FILE))
            .expect("Could not create chart stat file."),
    );

    serde_json::to_writer(char_stat_file, &**stats).expect("Could not write stats file");
}
