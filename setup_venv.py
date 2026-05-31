import os
import sys
import subprocess
from pathlib import Path

USER_FRIENDLY_VENV_PATH = "tools/common/.venv"

def enter_venv():
    # check if already in venv (set below before execv)
    if os.environ.get("NX_DECOMP_TOOLS_IN_VENV"):
        return
    venv_executable = Path(__file__).parent / ".venv" / "bin" / "python"
    if sys.executable == venv_executable:
        return
    setup_python_venv()
    os.environ["NX_DECOMP_TOOLS_IN_VENV"] = "1"
    os.execv(venv_executable, [venv_executable, *sys.argv])

def fail(error: str):
    print(">>> " + error)
    sys.exit(1)

def setup_python_venv():
    tools_root = Path(__file__).parent
    venv_path = tools_root / ".venv"
    venv_python = venv_path / "bin" / "python"
    venv_pip = venv_path / "bin" / "pip"

    if not venv_path.is_dir(follow_symlinks=True):
        if venv_path.exists():
            fail(f"error: {USER_FRIENDLY_VENV_PATH} exists and is not a directory!")
        # create venv
        print(f">>> creating {USER_FRIENDLY_VENV_PATH}")
        subprocess.check_call([sys.executable, "-m", "venv", venv_path])
    else:
        print(f">>> {USER_FRIENDLY_VENV_PATH} is already setup")
        # still fall through to ensure pip modules are up-to-date


    # for some reason just installing with pip install . fail to build
    # levenshtein, so we will use the shim approach
    print(">>> installing python dependencies")
    try:
        requirements = tools_root / "pip-requirements.txt"
        subprocess.check_call([
            venv_pip,
            "install",
            "-r",
            requirements
        ])
        # create shim for asm-differ
        # note the cd is important so diff_settings is processed correctly
        asm_differ_shim = venv_path / "bin" / "asm-differ"
        asm_differ_shim.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
PYTHON='{venv_python}'
cd '{tools_root}'
exec "$PYTHON" asm-differ/diff.py "$@"
""")
        os.chmod(asm_differ_shim, 0o755) # rwxr-xr-x

    except:
        print(sys.exc_info()[0])
        fail(f"error: delete {USER_FRIENDLY_VENV_PATH} and try again")
