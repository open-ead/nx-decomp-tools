# Renames functions in an IDA database to match the function names
# in the decompiled source code.

import csv
import idc
import os
from util import config

csv_path = config.get_functions_csv_path()

def can_overwrite_name(addr: int, new_name: str):
    if not new_name or new_name.startswith(("sub_", "nullsub_", "j_")):
        return False

    old_name: str = idc.get_name(addr)
    # If we don't have an existing name, then the function can always be renamed.
    if not old_name:
        return True

    # Auto-generated names can be overwritten.
    if old_name.startswith(("sub_", "nullsub_", "j_")):
        return True

    # If the existing name is mangled, then it probably came from the function list CSV
    # so it can be overwritten.
    if old_name.startswith("_Z"):
        return True

    # Prefer mangled names to temporary names.
    if new_name.startswith("_Z"):
        return True

    # Otherwise, we return false to avoid losing temporary names.
    return False


with open(csv_path, "r") as f:
    reader = csv.reader(f)
    # Skip headers
    next(reader)
    for fn in reader:
        addr = int(fn[0], 16)
        name = fn[3]
        if can_overwrite_name(addr, name):
            idc.set_name(addr, name)
