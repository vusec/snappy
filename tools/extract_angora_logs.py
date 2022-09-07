from argparse import ArgumentParser
from pathlib import Path
import re
import tarfile
import io

import pandas as pd
from tqdm import tqdm

SUPPORTED_FUZZERS = ("snappy", "snappy_no_exit", "angora")


def process_archive(archive_path: Path):
    with tarfile.open(archive_path) as archive:
        log_file = archive.extractfile("corpus/angora_log.csv")
        df = pd.read_csv(io.TextIOWrapper(log_file))
        df["time"] = df["elapsed_secs"].apply(lambda s: pd.Timedelta(seconds=s))
        del df["elapsed_secs"]
    return df


def process_trials(config_dir: Path):
    config_data = pd.DataFrame()

    trial_dirs = list(config_dir.glob("trial-*"))
    for trial_dir in tqdm(trial_dirs):
        match = re.fullmatch("trial-([0-9]+)", trial_dir.name)
        if match is None:
            print(f"Could not match trial folder: {trial_dir.name}")
            exit(1)

        trial_id = int(match.group(1))

        # The last archive contains a snapshot at the end of the experiment.
        archives_dir = trial_dir / "corpus"
        archive_path = sorted(archives_dir.glob("corpus-archive-*.tar.gz"))[-1]

        df = process_archive(archive_path)
        df["trial"] = trial_id

        config_data = pd.concat([config_data, df])

    return config_data


def main(args):
    experiment_dir: Path = args.experiment_dir
    if not experiment_dir.is_dir():
        print(f"Could not find folder: {experiment_dir}")
        exit(1)

    config_dirs = list((experiment_dir / "experiment-folders").iterdir())

    experiment_data = pd.DataFrame()

    for config_dir in tqdm(config_dirs):
        benchmark, fuzzer = config_dir.name.rsplit("-", 1)
        if fuzzer not in SUPPORTED_FUZZERS:
            continue

        config_data = process_trials(config_dir)

        config_data["fuzzer"] = fuzzer
        config_data["benchmark"] = benchmark
        experiment_data = pd.concat([experiment_data, config_data])

    experiment_data["experiment"] = experiment_dir.name
    experiment_data.to_csv(args.output_path, index=False)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("experiment_dir", type=Path)
    parser.add_argument("output_path", type=Path)
    args = parser.parse_args()

    main(args)
