from pathlib import Path
from argparse import ArgumentParser
import tarfile
import csv
import numpy as np
import matplotlib.pyplot as plt
from tqdm import tqdm
import io
import scipy.stats as st
from collections import defaultdict
import math


def extract_execs_data(trial_folder: Path):
    corpus_folder = trial_folder / "corpus"
    archive_file = sorted(corpus_folder.glob("corpus-archive-*.tar.gz"))[-1]
    with tarfile.open(archive_file) as archive:
        log_file = archive.extractfile("corpus/angora_log.csv")
        reader = csv.DictReader(io.TextIOWrapper(log_file))

        time = []
        execs = []
        for row in reader:
            time.append(int(row["elapsed_secs"]))
            execs.append(int(row["num_execs"]))

    return (np.array(time), np.array(execs))


def plot_experiment(experiment_folder, ax, color, is_for_paper):
    execs_data = []
    max_time = 0
    for trial_folder in tqdm(list(experiment_folder.glob("trial-*"))):
        try:
            time, execs = extract_execs_data(trial_folder)
            execs_data.append((time, execs))

            if time[-1] > max_time:
                max_time = time[-1]
        except:
            tqdm.write(f"Could not load data from {trial_folder}")
            continue

    time_vals = np.linspace(0, max_time, 1000)

    execs_series = []
    for time, execs in execs_data:
        execs_interp = np.interp(time_vals, time, execs, right=None)
        execs_series.append(execs_interp)

    sample_size = len(execs_series)
    delta = 1.96 * math.sqrt(sample_size * 0.5 * (1 - 0.5))
    upper_ci = math.ceil(sample_size * 0.5 + delta) - 1
    lower_ci = math.ceil(sample_size * 0.5 - delta) - 1

    last_entry = None
    median_execs = []
    upper_std = []
    lower_std = []
    for execs_entry in zip(*execs_series):
        median = np.median(execs_entry)
        median_execs.append(median)

        execs_entry = list(execs_entry)
        execs_entry.sort()
        upper_std.append(execs_entry[upper_ci])
        lower_std.append(execs_entry[lower_ci])

        last_entry = execs_entry

    fuzzer_name = experiment_folder.name.rsplit(sep="-", maxsplit=1)[-1]
    if is_for_paper and fuzzer_name == "xray_snapshot":
        fuzzer_name = "snappy"

    if not is_for_paper:
        label = f"{fuzzer_name} ({len(execs_data)} reps)"
    else:
        label = fuzzer_name

    ax.plot(
        time_vals,
        median_execs,
        label=label,
        color=color,
    )
    ax.fill_between(time_vals, lower_std, upper_std, alpha=0.2, color=color)

    return last_entry


def generate_benchmark_plot(
    experiment_folders, benchmark_name, output_file, is_for_paper
):
    experiment_folders.sort(reverse=True)

    fig, ax = plt.subplots()

    if is_for_paper:
        fig.set_size_inches(3.5, 3)

    last_entries = []
    colors = ["tab:blue", "tab:orange", "tab:green"]
    for idx, experiment_folder in enumerate(experiment_folders):
        last_entry = plot_experiment(experiment_folder, ax, colors[idx], is_for_paper)
        last_entries.append(last_entry)

    if not is_for_paper:
        ax.set_title(benchmark_name)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Executions (#)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_file)

    U1, pval = st.mannwhitneyu(last_entries[0], last_entries[1], alternative="greater")
    median_0 = np.median(last_entries[0])
    median_1 = np.median(last_entries[1])
    print(f"U1: {U1}")
    print(f"p-value: {pval}")
    print(f"median_0: {median_0}")
    print(f"median_1: {median_1}")
    print(f"speedup: {median_0 / median_1:.2f}x")


def main(args):
    experiment_folders_dir: Path = args.experiment_folders_dir
    if not experiment_folders_dir.is_dir():
        print("Not a valid experiment-folders directory")
        exit(1)

    experiments = defaultdict(list)
    for experiment_folder in experiment_folders_dir.iterdir():
        benchmark_name = experiment_folder.name.rsplit(sep="-", maxsplit=1)[0]
        experiments[benchmark_name].append(experiment_folder)

    output_extension = "png" if not args.paper else "pdf"
    for benchmark_name, experiment_folders in experiments.items():
        print(f"Generating benchmark plot for {benchmark_name}")
        generate_benchmark_plot(
            experiment_folders,
            benchmark_name,
            args.plots_folder / f"speed_{benchmark_name}.{output_extension}",
            args.paper,
        )
        print()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("experiment_folders_dir", type=Path)
    parser.add_argument("plots_folder", type=Path)
    parser.add_argument("--paper", action="store_true")
    args = parser.parse_args()

    main(args)
