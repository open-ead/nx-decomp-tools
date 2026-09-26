import io
import csv
import typing as tp
from pathlib import Path

from .types import FunctionStatus, FunctionInfo
from .config import get_functions_csv_path

_markers = {
    "O": FunctionStatus.Matching,
    "m": FunctionStatus.Equivalent,
    "M": FunctionStatus.NonMatching,
    "W": FunctionStatus.Wip,
    "U": FunctionStatus.NotDecompiled,
    "L": FunctionStatus.NotDecompiled,
}

def parse_function_csv_entry(row) -> FunctionInfo:
    ea, stat, size, name = row
    status = _markers.get(stat, FunctionStatus.NotDecompiled)
    decomp_name = ""

    if status != FunctionStatus.NotDecompiled:
        decomp_name = name

    addr = int(ea, 16) - 0x7100000000
    return FunctionInfo(addr, name, int(size), decomp_name, stat == "L", status, row)


def get_functions(path: tp.Optional[Path] = None, version = None, all=False) -> tp.Iterable[FunctionInfo]:
    if path is None:
        path = get_functions_csv_path(version)
    with path.open() as f:
        reader = csv.reader(f)
        # Skip headers
        next(reader)
        for row in reader:
            try:
                entry = parse_function_csv_entry(row)
                # excluded library function
                if entry.library and not all:
                    continue
                yield entry
            except ValueError as e:
                raise Exception(f"Failed to parse line {reader.line_num}") from e


def add_decompiled_functions(new_matches: tp.Dict[int, str],
                             new_orig_names: tp.Optional[tp.Dict[int, str]] = None) -> None:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for func in get_functions():
        if new_orig_names is not None and func.status == FunctionStatus.NotDecompiled and func.addr in new_orig_names:
            func.raw_row[3] = new_orig_names[func.addr]
        if func.status == FunctionStatus.NotDecompiled and func.addr in new_matches:
            func.raw_row[3] = new_matches[func.addr]
        writer.writerow(func.raw_row)
    get_functions_csv_path().write_text(buffer.getvalue())
