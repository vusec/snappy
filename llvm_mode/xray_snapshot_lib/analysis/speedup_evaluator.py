import json
from argparse import ArgumentParser
from pathlib import Path
from tempfile import gettempdir
from shutil import rmtree
from datetime import timedelta
from matplotlib import pyplot as plt
from functools import reduce
import statistics
from tqdm import tqdm
import subprocess
from copy import copy
import csv
import yaml
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

REPETITIONS = 20


def generic_mean(sequence):
    return reduce(lambda x, y: x + y, sequence) / len(sequence)


def resolve_backtrace(
    symbolized_backtrace: List[List[str]], xray_map: Dict[str, List[int]]
) -> List[List[int]]:
    xray_backtrace = []
    for frame in symbolized_backtrace:
        function_ids = []
        for function_name in frame:
            try:
                function_ids += xray_map[function_name]
            except KeyError:
                # If a specific function was not instrumented, just skip it.
                # This happens for library functions that are not in the
                # instrumented binary.
                continue

        # Add frame to target backtrace only if at least one function in the
        # frame was instrumented. This skips frames in uninstrumented libraries
        if function_ids:
            xray_backtrace.append(function_ids)

    # XRay instrumentation expects the first frame encountered to be first in
    # the list
    return xray_backtrace[::-1]


def print_formatted_commandline(cmdline, exec_env):
    env_entries_str = [f"{key}='{value}'" for key, value in exec_env.items()]
    env_cmdline_str = " ".join(env_entries_str)
    cmdline_str = " ".join(cmdline)

    print(f"{env_cmdline_str} {cmdline_str}")


def run_target(
    test_case_path: Path,
    binary_path: Path,
    target_backtrace: List[List[int]],
    flags: List[str],
    temp_path: Path,
) -> Tuple[Optional[timedelta], Optional[timedelta]]:
    output_file_path = temp_path / "output_file"
    if output_file_path.is_file():
        output_file_path.unlink()

    exec_env = {
        "TRACER_ENABLED": "true",
        "TRACER_OUTPUT_FILE": str(output_file_path),
        "TRACER_MACHINE_READABLE": "true",
        "XRAY_SNAPSHOT_BACKTRACE": json.dumps(target_backtrace),
        "__AFL_DEFER_FORKSRV": "true",  # Do not initialize fork server
    }

    try:
        file_idx = flags.index("@@")
        flags = copy(flags)  # Do not modify flags array
        flags[file_idx] = str(test_case_path)
        stdin = None
    except ValueError:
        stdin = open(test_case_path, "rb")
    cmdline = [str(binary_path)] + flags

    subprocess.run(
        cmdline,
        stdin=stdin,
        env=exec_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if stdin is not None:
        stdin.close()

    if not output_file_path.is_file():
        print("No output file:")
        print_formatted_commandline(cmdline, exec_env)
        return (None, None)

    with open(output_file_path) as output_file:
        output_reader = csv.DictReader(output_file)
        analysis_output = next(iter(output_reader))

    execution_duration = timedelta(
        microseconds=int(analysis_output["execution_nanos"]) // 1000
    )

    from_first_tainted: Optional[timedelta] = None
    if analysis_output["target_function_entry_to_end_nanos_opt"] != "":
        from_first_tainted = timedelta(
            microseconds=int(analysis_output["target_function_entry_to_end_nanos_opt"])
            // 1000
        )
    else:
        print("Backtrace not matched")
        print_formatted_commandline(cmdline, exec_env)

    return (execution_duration, from_first_tainted)


def get_xray_map(binary_path: Path) -> Dict[str, List[int]]:
    completed_process = subprocess.run(
        ["llvm-xray", "extract", "--symbolize", "--no-demangle", str(binary_path)],
        capture_output=True,
    )
    xray_full_map = yaml.safe_load(completed_process.stdout)

    xray_map: Dict[str, List[int]] = defaultdict(list)
    for entry in xray_full_map:
        if entry["kind"] == "function-enter":
            xray_map[entry["function-name"]].append(entry["id"])

    return xray_map


def analyze_queue(
    config, binary_path: Path, flags: List[str], temp_path: Path
) -> Tuple[List[float], List[timedelta], List[timedelta]]:
    xray_map = get_xray_map(binary_path)

    speedups = []
    avg_execution_durations = []
    avg_optimized_durations = []
    for test_config in tqdm(config):
        input_path = Path(test_config["input_file"])
        target_backtrace = resolve_backtrace(test_config["target_backtrace"], xray_map)
        count = test_config["count"]

        if not input_path.is_file():
            print(f"Could not find input_file: {input_path}")
            continue

        execution_durations = []
        from_first_tainted_durations = []
        for _ in range(REPETITIONS):
            execution_duration, from_first_tainted_duration = run_target(
                input_path, binary_path, target_backtrace, flags, temp_path
            )

            # If we are not catching the target the first time, we never will
            if from_first_tainted_duration is None:
                break

            execution_durations.append(execution_duration)
            from_first_tainted_durations.append(from_first_tainted_duration)

        if not from_first_tainted_durations:
            # We were not able to hit the target for this configuration
            print(f"Target backtrace: {test_config['target_backtrace']}")
            continue

        avg_execution_duration = generic_mean(execution_durations)
        avg_from_first_tainted = generic_mean(from_first_tainted_durations)
        speedup = avg_execution_duration / avg_from_first_tainted
        for _ in range(count):
            avg_execution_durations.append(avg_execution_duration)
            avg_optimized_durations.append(avg_from_first_tainted)
            speedups.append(speedup)

    return speedups, avg_optimized_durations, avg_execution_durations


def dump_results(
    dump_path: Path,
    results: Tuple[List[float], List[timedelta], List[timedelta]],
    fieldnames=List[str],
):
    with open(dump_path, "w") as dump_file:
        writer = csv.DictWriter(dump_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in zip(*results):
            row_dict = {}
            for (fieldname, value) in zip(fieldnames, row):
                if isinstance(value, timedelta):
                    value /= timedelta(microseconds=1)
                row_dict[fieldname] = value
            writer.writerow(row_dict)


def main(args):
    if not args.config_path.is_file():
        print(f"could not find config file: {args.binary_path}")
        exit(1)

    if not args.binary_path.is_file():
        print(f"could not find target binary: {args.binary_path}")
        exit(1)

    if args.flags is not None:
        flags = args.flags.split(" ")
    else:
        flags = []

    with open(args.config_path) as config_file:
        config = json.load(config_file)

    temp_path = Path(gettempdir()) / "xray_snapshot_lib"
    temp_path.mkdir(exist_ok=True)

    speedups, avg_optimized_durations, avg_exec_durations = analyze_queue(
        config, args.binary_path, flags, temp_path
    )

    print(f"mean speedup on execution:\t{statistics.mean(speedups):.3}x")
    print(f"mean full execution duration:\t{generic_mean(avg_exec_durations)}")

    if args.dump_path is not None:
        dump_results(
            args.dump_path,
            (speedups, avg_optimized_durations, avg_exec_durations),
            ["speedup", "optimized_duration", "total_duration"],
        )

    fig, axes = plt.subplots(3, 1)
    fig.suptitle("Snapshotting with XRay")

    axes[0].set_xlabel("Speedup")
    axes[0].hist(speedups, bins=100)

    axes[1].set_xlabel("Optimized execution duration (us)")
    axes[1].hist(
        [
            exec_duration / timedelta(microseconds=1)
            for exec_duration in avg_optimized_durations
        ],
        bins=100,
        range=(0, 500),
    )
    axes[1].set_xlim(left=0, right=500)

    axes[2].set_xlabel("Full execution duration (us)")
    axes[2].hist(
        [
            exec_duration / timedelta(microseconds=1)
            for exec_duration in avg_exec_durations
        ],
        bins=100,
        range=(0, 500),
    )
    axes[2].set_xlim(left=0, right=500)

    fig.tight_layout()
    plt.savefig(args.output_path)

    rmtree(temp_path)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-c", "--config-path", required=True, type=Path)
    parser.add_argument("-o", "--output-path", required=True, type=Path)
    parser.add_argument("-d", "--dump-path", type=Path)
    parser.add_argument("-b", "--binary-path", required=True, type=Path)
    parser.add_argument("-f", "--flags")

    args = parser.parse_args()
    main(args)
