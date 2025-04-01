from . config import get_repo_root
import platform
import os

def get_tools_bin_dir():
    path = get_repo_root() / 'tools' / 'common' / 'nx-decomp-tools-binaries'
    system = platform.system()
    if system == "Linux":
        return str(path) + "/linux/"
    if system == "Darwin":
        return str(path) + "/macos/"
    return ""

def try_find_external_tool(tool: str):
    return os.environ.get("NX_DECOMP_TOOLS_%s" % tool.upper().replace("-", "_"))

def find_tool(tool: str):
    tool_from_env = try_find_external_tool(tool)

    if tool_from_env is None:
        return get_tools_bin_dir() + tool

    return tool_from_env
