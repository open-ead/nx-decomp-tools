# Renames functions in an IDA database to match the function names
# in the decompiled source code.

import csv
import idc
import os
from util import config

csv_path = config.get_functions_csv_path()

with open(csv_path, "r") as f:
    reader = csv.reader(f)
    # Skip headers
    next(reader)
    for fn in reader:
        addr = int(fn[0], 16)
        name = fn[3]
        if name and not name.startswith(("sub_", "nullsub_", "j_")):
            idc.set_name(addr, name)
