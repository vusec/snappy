from argparse import ArgumentParser
from pathlib import Path
import tarfile
import csv
import pandas as pd
import numpy as np
import base64
import codecs
import json
from hdrh.histogram import HdrHistogram
from tqdm import tqdm

FUZZER_NAME = "xray_snapshot"

DELAYED_EXECS_MICROS_HIST_FILE = "delayed_execs_micros.hist"
PLAIN_EXECS_MICROS_HIST_FILE = "plain_execs_micros.hist"
SNAPSHOT_MICROS_HIST_FILE = "snapshot_micros.hist"
ANGORA_LOG_FILE = "angora_log.csv"
SNAPSHOT_POSITIONS_FILE = "snapshot_positions.json"


def load_hdr_histogram(hist_file) -> HdrHistogram:
    hist_data = hist_file.read()

    # The Base64 is a work around for a bug in the deserializer,
    # see https://github.com/HdrHistogram/HdrHistogram_py/issues/29
    b64_hist_data = base64.b64encode(hist_data)
    return HdrHistogram.decode(b64_hist_data)


def analyze_threshold(log_data):
    reader = csv.DictReader(log_data)
    last_threshold = 0
    for row in reader:
        last_threshold = (
            float(row["snapshot_threshold"])
            if row["snapshot_threshold"] != ""
            else float("+inf")
        )
    return last_threshold


def analyze_unique_snapshots(unique_snapshots_data):
    try:
        unique_snapshots = json.load(unique_snapshots_data)
        return len(unique_snapshots)
    except json.decoder.JSONDecodeError:
        return np.nan


def analyze_trial(trial_dir: Path):
    corpus_dir = trial_dir / "corpus"
    archive_file = sorted(corpus_dir.glob("corpus-archive-*.tar.gz"))[-1]
    with tarfile.open(archive_file) as archive:
        delayed_execs_micros_hist = load_hdr_histogram(
            archive.extractfile(f"corpus/{DELAYED_EXECS_MICROS_HIST_FILE}")
        )
        plain_execs_micros_hist = load_hdr_histogram(
            archive.extractfile(f"corpus/{PLAIN_EXECS_MICROS_HIST_FILE}")
        )
        snapshot_micros_hist = load_hdr_histogram(
            archive.extractfile(f"corpus/{SNAPSHOT_MICROS_HIST_FILE}")
        )
        log_data = codecs.getreader("utf-8")(
            archive.extractfile(f"corpus/{ANGORA_LOG_FILE}")
        )
        last_threshold = analyze_threshold(log_data)
        unique_snapshots_data = codecs.getreader("utf-8")(
            archive.extractfile(f"corpus/{SNAPSHOT_POSITIONS_FILE}")
        )
        num_unique_snapshots = analyze_unique_snapshots(unique_snapshots_data)

    trial_data = pd.DataFrame(
        {
            "plain_execs_micros_median": [
                plain_execs_micros_hist.get_value_at_percentile(50)
            ],
            "delayed_execs_micros_median": [
                delayed_execs_micros_hist.get_value_at_percentile(50)
            ],
            "snapshot_micros_median": [
                snapshot_micros_hist.get_value_at_percentile(50)
            ],
            "last_threshold": [last_threshold],
            "unique_snapshots": [num_unique_snapshots],
        }
    )

    return trial_data


def analyze_config(config_dir: Path):
    config_data = pd.DataFrame()
    for trial_dir in tqdm(list(config_dir.glob("trial-*"))):
        trial_num = int(trial_dir.name.rsplit(sep="-", maxsplit=1)[1])
        trial_data = analyze_trial(trial_dir)

        trial_data["trial"] = trial_num
        config_data = pd.concat([config_data, trial_data], ignore_index=True)

    return config_data


def main(args):
    experiment_folders_dir: Path = args.experiment_folder / "experiment-folders"
    if not experiment_folders_dir.is_dir():
        print("Not a valid experiment folder")
        exit(1)

    benchmarks = set()
    for experiment_folder in experiment_folders_dir.glob(f"*-{FUZZER_NAME}"):
        benchmark = experiment_folder.name.rsplit(sep="-", maxsplit=1)[0]
        benchmarks.add(benchmark)

    experiment_data = pd.DataFrame()
    for benchmark in benchmarks:
        print(f"Analyzing trials for {benchmark}")
        config_data = analyze_config(
            experiment_folders_dir / f"{benchmark}-{FUZZER_NAME}"
        )
        config_data["benchmark"] = benchmark
        experiment_data = pd.concat([experiment_data, config_data], ignore_index=True)

    experiment_data.to_csv(args.experiment_folder / "paper_stats.csv")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("experiment_folder", type=Path)
    args = parser.parse_args()

    main(args)
