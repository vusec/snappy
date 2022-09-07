#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import yaml
import json


def main(args):
    with open(args.xray_map) as map_file:
        map_data = yaml.safe_load(map_file)

    if args.kind == "ENTRY":
        target_kind_yaml = "function-enter"
    elif args.kind == "EXIT":
        target_kind_yaml = "function-exit"
    else:
        raise Exception("Invalid hook kind")

    target_ids = [
        entry["id"]
        for entry in map_data
        if entry["function-name"] == args.function_name
        and entry["kind"] == target_kind_yaml
    ]

    snapshot_target = {
        "target_ids": target_ids,
        "target_kind": args.kind,
        "hit_count": args.hit_count,
    }

    snapshot_target_json = json.dumps(snapshot_target)

    print(snapshot_target_json)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("xray_map", type=Path)
    parser.add_argument("function_name", type=str)
    parser.add_argument("--kind", type=str, choices=["ENTRY", "EXIT"], default="ENTRY")
    parser.add_argument("--hit_count", type=int, default=1)
    args = parser.parse_args()

    main(args)