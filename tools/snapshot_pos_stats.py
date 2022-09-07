from argparse import ArgumentParser
from pathlib import Path
from collections import namedtuple, defaultdict
import json

TargetHookInfo = namedtuple(
    "TargetHookInfo", ["symbol_name", "symbol_type", "hit_count"]
)


def main(args):
    with open(args.output_data / "snapshot_positions.json") as pos_file:
        data = json.load(pos_file)

    snapshots = []
    unique_positions = defaultdict(int)
    unique_test_cases = defaultdict(int)
    for entry in data:
        position_dict = entry[0][0]
        position = TargetHookInfo(**position_dict)
        test_case = entry[0][1]
        count = entry[1]

        unique_positions[position] += count
        unique_test_cases[test_case] += count

        snapshots.append(((position, test_case), count))

    snapshots.sort(key=lambda x: -x[1])
    print("Top 10 snapshots:")
    for snapshot, count in snapshots[:10]:
        position, test_case = snapshot
        print(f"{position},\ttest_case {test_case}:\t{count}")
    print()
    print(f"Different snapshots: {len(data)}")

    print()
    unique_positions_list = list(unique_positions.items())
    unique_positions_list.sort(key=lambda x: -x[1])
    print("Top 10 unique positions:")
    for position, count in unique_positions_list[:10]:
        print(f"{position}:\t{count}")
    print()
    print(f"Unique positions: {len(unique_positions)}")

    print()
    unique_test_cases_list = list(unique_test_cases.items())
    unique_test_cases_list.sort(key=lambda x: -x[1])
    print("Top 10 test cases:")
    for test_case, count in unique_test_cases_list[:10]:
        print(f"test_case {test_case}:\t{count}")
    print()
    print(f"Unique test cases: {len(unique_test_cases)}")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("output_data", type=Path)
    args = parser.parse_args()

    main(args)
