import subprocess
import sys

from nx_decomp_tools.util import fail, find_tool, config

def install_viking():
    print(">>>> installing viking (tools/check)")

    src_path = config.NX_DECOMP_TOOLS_PATH / "viking"
    install_path = config.get_tools_root()

    try:
        subprocess.check_call(["cargo", "build", "--manifest-path", src_path / "Cargo.toml", "--release"])
        for tool in ["check", "listsym", "decompme"]:
            (src_path / "target" / "release" / tool).rename(install_path / tool)
    except FileNotFoundError:
        print(sys.exc_info()[0])
        fail("error: install cargo (rust) and try again")
