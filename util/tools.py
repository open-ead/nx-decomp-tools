from . config import get_repo_root
import platform
import os
import shutil

def get_tools_bin_dir():
    path = get_repo_root() / 'tools' / 'common' / 'nx-decomp-tools-binaries'
    system = platform.system()
    if system == "Linux":
        return str(path) + "/linux/"
    if system == "Darwin":
        return str(path) + "/macos/"
    return ""

def find_tool(tool):
    executable = shutil.which(tool)
    if executable is not None:
        return executable

    return _get_tool_binary_path() + tool
