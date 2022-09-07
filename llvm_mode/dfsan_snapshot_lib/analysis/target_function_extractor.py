from argparse import ArgumentParser
from pathlib import Path
import sqlite3
from contextlib import closing
import cbor
import subprocess
import json
from tempfile import gettempdir
from copy import copy
from collections import Counter
from functools import reduce
from shutil import rmtree
from tqdm import tqdm


INSTR_SUCCESS_EXIT_CODE = 42
INSTR_FAILURE_EXIT_CODE = 24


def generic_mean(sequence):
    return reduce(lambda x, y: x + y, sequence) / len(sequence)


def get_condition_bytes_state(db_path, queue_path):
    with closing(sqlite3.connect(db_path)) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute(
                """
                SELECT test_case_hash, analysis_dump
                FROM analysis_states JOIN discoveries USING (discovery_id)
                WHERE analysis_id = (
                    SELECT id
                    FROM analysis_types
                    WHERE description = "condition_bytes"
                )
                ORDER BY discovery_id ASC
                """
            )
            result = cursor.fetchall()

    # In order to get the final result of the analysis, the global state needs to be
    # reconstructed. This guarantees that each condition appears only once. The
    # information preserved is the one for the earliest observation in the trace.
    condition_bytes_state = {}
    for (test_case_name, cbor_dump) in result:
        test_case_path = queue_path / test_case_name
        assert test_case_path.is_file()

        condition_bytes_update = cbor.loads(cbor_dump)
        for (condition_id, taint_info) in condition_bytes_update.items():
            if condition_id not in condition_bytes_state:
                condition_bytes_state[condition_id] = (
                    tuple(taint_info["input_offsets"]),
                    test_case_path,
                )

    return condition_bytes_state


def print_formatted_commandline(cmdline, exec_env, input_offsets, temp_path):
    env_entries_str = [f"{key}={value}" for key, value in exec_env.items()]
    env_cmdline_str = " ".join(env_entries_str)
    cmdline_str = " ".join(cmdline)

    if input_offsets is not None:
        offsets_list_str = f"{list(input_offsets)}"
        offsets_file_path = temp_path / "offsets_file"
        print(
            f"Command line: echo '{offsets_list_str}' > {offsets_file_path} && ", end=""
        )

    print(f"{env_cmdline_str} {cmdline_str}")


def run_target(
    test_case_path, binary_path, flags, temp_path, input_offsets=None,
):
    output_file_path = temp_path / "output_file"
    if output_file_path.is_file():
        output_file_path.unlink()

    exec_env = {
        "DFSAN_OPTIONS": "strict_data_dependencies=0",
        "TRACER_INPUT_FILE": str(test_case_path),
        "TRACER_OUTPUT_FILE": str(output_file_path),
    }

    if input_offsets is not None:
        offsets_file_path = temp_path / "offsets_file"

        with open(offsets_file_path, "w") as offsets_file:
            json.dump(input_offsets, offsets_file)
            offsets_file_path = offsets_file.name

        exec_env["TRACER_TAINTED_OFFSETS_FILE"] = str(offsets_file_path)
    else:
        exec_env["TRACER_ALL_TAINTED"] = "true"

    try:
        file_idx = flags.index("@@")
        flags = copy(flags)  # Do not modify flags array
        flags[file_idx] = str(test_case_path)
        stdin = None
    except ValueError:
        stdin = open(test_case_path, "rb")
    cmdline = [str(binary_path)] + flags

    completed_process = subprocess.run(
        cmdline,
        stdin=stdin,
        env=exec_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if stdin is not None:
        stdin.close()

    if completed_process.returncode == INSTR_SUCCESS_EXIT_CODE:
        with open(output_file_path) as output_file:
            return tuple(
                tuple(frame_symbols) for frame_symbols in json.load(output_file)
            )
    elif completed_process.returncode == INSTR_FAILURE_EXIT_CODE:
        print("Instrumentation failed!")
        print_formatted_commandline(cmdline, exec_env, input_offsets, temp_path)
        return None
    else:
        print("No tainted load found for test case!")
        print_formatted_commandline(cmdline, exec_env, input_offsets, temp_path)
        return None


def analyze_with_conditions(args, flags, temp_path):
    print("Calculating speedup when targeting conditions")

    if args.all_tainted:
        print("Supposing no taint information is available")
    else:
        print("Supposing taint information is available")

    db_path = args.collabfuzz_output_dir / "out/run_info.sqlite"
    if not db_path.is_file():
        print(f"could not find database: {db_path}")
        exit(1)

    queue_path = args.collabfuzz_output_dir / "out/queue"
    if not queue_path.is_dir():
        print(f"could not find queue folder: {queue_path}")
        exit(1)

    condition_bytes_state = get_condition_bytes_state(db_path, queue_path)

    # Often multiple conditions are tainted by the same bytes using the same test case.
    # In order to avoid running multiple times with the same configuration, duplicates
    # are counted.
    test_configs_to_counts = Counter(condition_bytes_state.values())

    result_configs_to_counts = Counter()
    for (test_case_offsets, test_case_path), count in tqdm(
        test_configs_to_counts.items()
    ):
        target_backtrace = run_target(
            test_case_path,
            args.binary_path,
            flags,
            temp_path,
            None if args.all_tainted else test_case_offsets,
        )

        if target_backtrace is None:
            continue

        result_config = (test_case_path, target_backtrace)
        result_configs_to_counts[result_config] += count

    return result_configs_to_counts


def analyze_with_queue(args, flags, temp_path):
    print("Calculating speedup when fuzzing generic test cases")
    print("No taint information available by construction")

    queue_path = args.afl_queue_dir
    if not queue_path.is_dir():
        print(f"could not find queue folder: {queue_path}")
        exit(1)

    result_configs_to_counts = Counter()
    for test_case_path in tqdm(list(queue_path.iterdir())):
        if not test_case_path.is_file():
            continue

        target_backtrace = run_target(
            test_case_path, args.binary_path, flags, temp_path,
        )

        if target_backtrace is None:
            continue

        result_config = (test_case_path, target_backtrace)
        result_configs_to_counts[result_config] += 1

    return result_configs_to_counts


def analyze_with_byte_tracer_state(args, flags, temp_path):
    print("Calculating speedup when targeting conditions")

    if not args.bytes_tracer_state_path.is_file():
        print(f"could not find database: {args.bytes_tracer_state_path}")
        exit(1)

    with open(args.bytes_tracer_state_path) as bytes_tracer_state_file:
        condition_bytes_dump = json.load(bytes_tracer_state_file)

        # Test configurations need to be unmutable
        condition_bytes_state = {}
        for (condition_id, dumped_info) in condition_bytes_dump.items():
            parsed_info = (tuple(dumped_info[0]), Path(dumped_info[1]))
            condition_bytes_state[condition_id] = parsed_info

    if args.all_tainted:
        print("Supposing no taint information is available")
    else:
        print("Supposing taint information is available")

    # Often multiple conditions are tainted by the same bytes using the same test case.
    # In order to avoid running multiple times with the same configuration, duplicates
    # are counted.
    test_configs_to_counts = Counter(condition_bytes_state.values())

    result_configs_to_counts = Counter()
    for (test_case_offsets, test_case_path), count in tqdm(
        test_configs_to_counts.items()
    ):
        target_backtrace = run_target(
            test_case_path,
            args.binary_path,
            flags,
            temp_path,
            None if args.all_tainted else test_case_offsets,
        )

        if target_backtrace is None:
            continue

        result_config = (test_case_path, target_backtrace)
        result_configs_to_counts[result_config] += count

    return result_configs_to_counts


def main(args):
    if not args.binary_path.is_file():
        print(f"could not find target binary: {args.binary_path}")
        exit(1)

    if args.flags is not None:
        flags = args.flags.split(" ")
    else:
        flags = []

    temp_path = Path(gettempdir()) / "dfsan_snapshot_lib"
    temp_path.mkdir(exist_ok=True)

    if args.collabfuzz_output_dir is not None:
        result_config_to_counts = analyze_with_conditions(args, flags, temp_path)
    elif args.afl_queue_dir is not None:
        result_config_to_counts = analyze_with_queue(args, flags, temp_path)
    elif args.bytes_tracer_state_path is not None:
        result_config_to_counts = analyze_with_byte_tracer_state(args, flags, temp_path)
    else:
        print("specify either --collabfuzz-output-dir or --afl-queue-dir")
        exit(1)

    output_json = []
    for (test_case_path, target_backtrace), count in result_config_to_counts.items():
        output_json.append(
            {
                "input_file": str(test_case_path),
                "target_backtrace": target_backtrace,
                "count": count,
            }
        )

    with open(args.output_path, "w") as output_file:
        json.dump(output_json, output_file, indent=2)

    rmtree(temp_path)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-i", "--collabfuzz-output-dir", type=Path)
    parser.add_argument("-q", "--afl-queue-dir", type=Path)
    parser.add_argument("-j", "--bytes-tracer-state-path", type=Path)
    parser.add_argument("-o", "--output-path", required=True, type=Path)
    parser.add_argument("-b", "--binary-path", required=True, type=Path)
    parser.add_argument("-f", "--flags")
    parser.add_argument("-a", "--all-tainted", action="store_true")

    args = parser.parse_args()

    main(args)
