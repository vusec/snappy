import base64
from hdrh.histogram import HdrHistogram
from argparse import ArgumentParser
from pathlib import Path
from matplotlib import pyplot as plt
from typing import Optional
import tarfile
import numpy as np
import csv
import codecs

EXECS_PER_SNAP_COND_HIST_FILE_NAME = "execs_per_snap_cond.hist"
EXECS_PER_SNAPSHOT_HIST_FILE_NAME = "execs_per_snapshot.hist"
DELAYED_EXECS_MICROS_HIST_FILE = "delayed_execs_micros.hist"
PLAIN_EXECS_MICROS_HIST_FILE = "plain_execs_micros.hist"
TRACK_MICROS_HIST_FILE = "track_micros.hist"
SNAPSHOT_MICROS_HIST_FILE = "snapshot_micros.hist"
ANGORA_LOG_FILE = "angora_log.csv"


def load_hdr_histogram(hist_file) -> HdrHistogram:
    hist_data = hist_file.read()

    # The Base64 is a work around for a bug in the deserializer,
    # see https://github.com/HdrHistogram/HdrHistogram_py/issues/29
    b64_hist_data = base64.b64encode(hist_data)
    return HdrHistogram.decode(b64_hist_data)


def calculate_median(hist) -> np.ndarray:
    return hist.get_value_at_percentile(50)


def plot_linear_hdr_histogram(
    hist: HdrHistogram,
    axes,
    bins: int,
    x_max: Optional[int],
    print_ranges=False,
    percentage=True,
    mult_by_x=False,
    y_lim=None,
):
    max_value = x_max if x_max is not None else hist.get_max_value()
    step_size = max_value / bins
    total_values = hist.get_total_count()

    x_values = []
    height_values = []
    for item in hist.get_linear_iterator(step_size):
        x_value = (item.value_iterated_to + item.value_iterated_from) / 2
        x_values.append(x_value)

        if percentage:
            height_value = item.count_added_in_this_iter_step / total_values
        elif mult_by_x:
            height_value = item.count_added_in_this_iter_step * x_value
        else:
            height_value = item.count_added_in_this_iter_step
        height_values.append(height_value)

        if print_ranges:
            range_str = (
                f"[{item.value_iterated_from:.2f}, {item.value_iterated_to:.2f})"
            )
            print(f"{range_str}: {item.count_added_in_this_iter_step}")

        # This condition will trigger only if `x_max` was set
        if item.value_iterated_to > max_value:
            break

    axes.set_xlim(0, max_value)
    if y_lim is not None:
        axes.set_ylim(top=y_lim)

    return axes.bar(x_values, height_values, step_size)


def plot_execs_per_snap_cond_hist(
    hist: HdrHistogram, axes, bins: int, max_execs: Optional[int], y_lim=None
):
    plot_linear_hdr_histogram(
        hist, axes, bins, max_execs, percentage=False, y_lim=y_lim
    )
    axes.set_xlabel("Executions per snapshottable condition (#)")


def plot_execs_per_snapshot_hist(
    hist: HdrHistogram, axes, bins: int, max_execs: Optional[int], y_lim=None
):
    plot_linear_hdr_histogram(
        hist, axes, bins, max_execs, percentage=False, y_lim=y_lim
    )
    axes.set_xlabel("Executions per delayed snapshot (#)")


def plot_delayed_execs_micros_hist(
    hist: HdrHistogram,
    axes,
    bins: int,
    max_exec_micros: Optional[int],
    max_exec_perc: Optional[float],
):
    plot_linear_hdr_histogram(hist, axes, bins, max_exec_micros)

    median = calculate_median(hist)
    axes.axvline(median, c="y")

    axes.set_xlabel("Delayed execution time (us)")
    if max_exec_perc is not None:
        axes.set_ybound(upper=max_exec_perc)


def plot_plain_execs_micros_hist(
    hist: HdrHistogram,
    axes,
    bins: int,
    max_exec_micros: Optional[int],
    max_exec_perc: Optional[float],
):
    plot_linear_hdr_histogram(hist, axes, bins, max_exec_micros)

    median = calculate_median(hist)
    axes.axvline(median, c="y")

    axes.set_xlabel("Plain execution time (us)")
    if max_exec_perc is not None:
        axes.set_ybound(upper=max_exec_perc)


def plot_track_micros_hist(
    hist: HdrHistogram, axes, bins: int, max_track_micros: Optional[int]
):
    plot_linear_hdr_histogram(
        hist, axes, bins, max_track_micros, percentage=False, mult_by_x=True
    )

    axes.set_xlabel("Track time (us)")
    axes.set_ylabel("Time spent running (us)")


def plot_snapshot_micros_hist(
    hist: HdrHistogram, axes, bins: int, max_snapshot_micros: Optional[int]
):
    plot_linear_hdr_histogram(hist, axes, bins, max_snapshot_micros)

    median = calculate_median(hist)
    axes.axvline(median, c="y")

    axes.set_xlabel("Snapshot time (us)")


def plot_threshold(elapsed_secs, threshold, axes):
    axes.plot(elapsed_secs, threshold)
    axes.set_xlabel("Time (s)")
    axes.set_ylabel("Snapshot threshold")


def print_threshold_stats(elapsed_secs, threshold):
    time_vals = np.linspace(0, elapsed_secs[-1], 360)
    threshold_interp = np.interp(time_vals, elapsed_secs, threshold)

    zero_perc = np.count_nonzero(threshold_interp == 0) / len(threshold_interp)
    print(f"0 threshold: {zero_perc * 100:.2f}% of the time")

    inf_perc = np.count_nonzero(threshold_interp == np.inf) / len(threshold_interp)
    print(f"+inf threshold: {inf_perc * 100:.2f}% of the time")


def get_snapshot_benefit(x, execs_per_snapshot_hist, ammort_execs):
    benefit = 0

    for value in execs_per_snapshot_hist.get_recorded_iterator():
        # Pick only values after the snapshot
        if value.value_iterated_to < x:
            continue

        benefit += (
            value.value_iterated_to - (x + ammort_execs)
        ) * value.count_added_in_this_iter_step

    return benefit


def load_data_from_output_dir(output_dir: Path):
    with open(output_dir / EXECS_PER_SNAP_COND_HIST_FILE_NAME, "rb") as hist_file:
        execs_per_snap_cond_hist = load_hdr_histogram(hist_file)
    with open(output_dir / EXECS_PER_SNAPSHOT_HIST_FILE_NAME, "rb") as hist_file:
        execs_per_snapshot_hist = load_hdr_histogram(hist_file)
    with open(output_dir / DELAYED_EXECS_MICROS_HIST_FILE, "rb") as hist_file:
        delayed_execs_micros_hist = load_hdr_histogram(hist_file)
    with open(output_dir / PLAIN_EXECS_MICROS_HIST_FILE, "rb") as hist_file:
        plain_execs_micros_hist = load_hdr_histogram(hist_file)
    with open(output_dir / TRACK_MICROS_HIST_FILE, "rb") as hist_file:
        track_micros_hist = load_hdr_histogram(hist_file)
    with open(output_dir / SNAPSHOT_MICROS_HIST_FILE, "rb") as hist_file:
        snapshot_micros_hist = load_hdr_histogram(hist_file)

    with open(output_dir / ANGORA_LOG_FILE) as log_file:
        reader = csv.DictReader(log_file)
        elapsed_secs_data = []
        threshold_data = []
        for row in reader:
            elapsed_secs_data.append(int(row["elapsed_secs"]))
            threshold_data.append(int(row["snapshot_threshold"]))

    return (
        execs_per_snap_cond_hist,
        execs_per_snapshot_hist,
        delayed_execs_micros_hist,
        plain_execs_micros_hist,
        track_micros_hist,
        snapshot_micros_hist,
        (elapsed_secs_data, threshold_data),
    )


def load_data_from_archive(archive_path: Path):
    with tarfile.open(archive_path) as tar_file:
        execs_per_snap_cond_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{EXECS_PER_SNAP_COND_HIST_FILE_NAME}")
        )
        execs_per_snapshot_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{EXECS_PER_SNAPSHOT_HIST_FILE_NAME}")
        )
        delayed_execs_micros_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{DELAYED_EXECS_MICROS_HIST_FILE}")
        )
        plain_execs_micros_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{PLAIN_EXECS_MICROS_HIST_FILE}")
        )
        track_micros_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{TRACK_MICROS_HIST_FILE}")
        )
        snapshot_micros_hist = load_hdr_histogram(
            tar_file.extractfile(f"corpus/{SNAPSHOT_MICROS_HIST_FILE}")
        )

        log_data = codecs.getreader("utf-8")(
            tar_file.extractfile(f"corpus/{ANGORA_LOG_FILE}")
        )
        reader = csv.DictReader(log_data)
        elapsed_secs_data = []
        threshold_data = []
        for row in reader:
            elapsed_secs_data.append(int(row["elapsed_secs"]))
            threshold = (
                float(row["snapshot_threshold"])
                if row["snapshot_threshold"] != ""
                else float("+inf")
            )
            threshold_data.append(threshold)

    return (
        execs_per_snap_cond_hist,
        execs_per_snapshot_hist,
        delayed_execs_micros_hist,
        plain_execs_micros_hist,
        track_micros_hist,
        snapshot_micros_hist,
        (elapsed_secs_data, threshold_data),
    )


def main(args):
    fig, axs = plt.subplots(4, 2)

    if args.output_data.is_dir():
        (
            execs_per_snap_cond_hist,
            execs_per_snapshot_hist,
            delayed_execs_micros_hist,
            plain_execs_micros_hist,
            track_micros_hist,
            snapshot_micros_hist,
            (elapsed_secs_data, threshold_data),
        ) = load_data_from_output_dir(args.output_data)
    elif args.output_data.is_file():
        (
            execs_per_snap_cond_hist,
            execs_per_snapshot_hist,
            delayed_execs_micros_hist,
            plain_execs_micros_hist,
            track_micros_hist,
            snapshot_micros_hist,
            (elapsed_secs_data, threshold_data),
        ) = load_data_from_archive(args.output_data)
    else:
        print(f"Could not access: {args.output_data}")
        exit(1)

    plot_execs_per_snap_cond_hist(
        execs_per_snap_cond_hist,
        axs[0, 1],
        args.bins,
        args.max_execs,
        args.snapshot_y_lim,
    )
    plot_execs_per_snapshot_hist(
        execs_per_snapshot_hist,
        axs[1, 1],
        args.bins,
        args.max_execs,
        args.snapshot_y_lim,
    )
    plot_delayed_execs_micros_hist(
        delayed_execs_micros_hist,
        axs[1, 0],
        args.bins,
        args.max_exec_micros,
        args.max_exec_perc,
    )
    plot_plain_execs_micros_hist(
        plain_execs_micros_hist,
        axs[0, 0],
        args.bins,
        args.max_exec_micros,
        args.max_exec_perc,
    )
    plot_track_micros_hist(
        track_micros_hist,
        axs[3, 0],
        args.bins,
        args.max_track_micros,
    )
    plot_snapshot_micros_hist(
        snapshot_micros_hist,
        axs[2, 0],
        args.bins,
        args.max_snapshot_micros,
    )
    plot_threshold(elapsed_secs_data, threshold_data, axs[3, 1])
    print_threshold_stats(elapsed_secs_data, threshold_data)

    median_delayed_execs_micros = calculate_median(delayed_execs_micros_hist)
    median_plain_execs_micros = calculate_median(plain_execs_micros_hist)
    median_snapshot_micros = calculate_median(snapshot_micros_hist)

    if median_delayed_execs_micros <= median_plain_execs_micros:
        ammort_execs = median_snapshot_micros / (
            median_plain_execs_micros - median_delayed_execs_micros
        )
        print(f"Executions to ammortize snapshot: {ammort_execs:.2f}")

        max_value = execs_per_snap_cond_hist.get_value_at_percentile(99.9)
        x_values = np.linspace(0, max_value)
        y_values = np.array(
            [
                get_snapshot_benefit(x_value, execs_per_snap_cond_hist, ammort_execs)
                for x_value in x_values
            ]
        )

        axs[2, 1].plot(x_values, y_values)
        axs[2, 1].set_xlim(0, axs[0, 1].get_xlim()[1])
        axs[2, 1].set_xlabel("Skipped executions (#)")
        axs[2, 1].axhline(0, color="r")

        max_idx = y_values.argmax()
        ammort_window_start = x_values[max_idx]

        print(
            f"Maximum prob of amortizing snapshot: "
            + f"({ammort_window_start:.2f}, {y_values.max():.4f})"
        )

        axs[0, 1].axvspan(
            ammort_window_start,
            ammort_window_start + ammort_execs,
            color="red",
            alpha=0.2,
        )
        axs[1, 1].axvspan(
            0,
            ammort_execs,
            color="red",
            alpha=0.2,
        )
    else:
        print(
            "Delayed executions slower than plain ones: "
            + f"{median_delayed_execs_micros} us > {median_plain_execs_micros} us"
        )

    fig.set_size_inches(10, 10)
    fig.tight_layout()

    if args.output is None:
        plt.show()
    else:
        fig.savefig(args.output)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("output_data", type=Path)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--bins", type=int, default=80)
    parser.add_argument("--max-execs", type=int, default=None)
    parser.add_argument("--max-exec-micros", type=int, default=None)
    parser.add_argument("--max-track-micros", type=int, default=None)
    parser.add_argument("--max-snapshot-micros", type=int, default=None)
    parser.add_argument("--max-exec-perc", type=float, default=None)
    parser.add_argument("--snapshot-y-lim", type=float, default=None)
    args = parser.parse_args()

    main(args)
