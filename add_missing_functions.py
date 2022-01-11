#!/usr/bin/env python3

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, Set, List

from util import utils


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="Path to function CSV to merge")
    args = parser.parse_args()

    csv_path = Path(args.csv_path)

    known_fn_addrs: Set[int] = {func.addr for func in utils.get_functions(all=True)}
    names: Dict[int, str] = {func.addr: func.name for func in utils.get_functions(all=True)}
    new_fns: List[utils.FunctionInfo] = []
    for func in utils.get_functions(csv_path, all=True):
        if func.addr in known_fn_addrs:
            if names[func.addr] == "" and not func.name.startswith("_Z"):
                names[func.addr] = func.name
        else:
            new_fns.append(func)

    new_fn_list: List[utils.FunctionInfo] = []
    new_fn_list.extend(utils.get_functions(all=True))
    new_fn_list.extend(new_fns)
    new_fn_list.sort(key=lambda func: func.addr)

    # Output the modified function CSV.
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow("Address,Quality,Size,Name".split(","))
    for func in new_fn_list:
        if func.addr in names:
            func.raw_row[3] = names[func.addr]
        writer.writerow(func.raw_row)


if __name__ == "__main__":
    main()
