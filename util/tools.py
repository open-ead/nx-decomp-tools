from . config import get_repo_root
import platform
import os
import shutil

def try_find_binaries_repo_tool(tool: str):
    binaries_repo_path = get_repo_root() / 'toolchain' / 'nx-decomp-tools-binaries'
    system = platform.system()
    tool_path = str(binaries_repo_path)
    if system == "Linux":
        tool_path += "/linux/"
    if system == "Darwin":
        tool_path += "/macos/"
    tool_path += tool
    if os.path.isfile(tool_path):
        return tool_path
    return None

def try_find_toolchain_tool(tool: str):
    toolchain_tool_path = get_repo_root() / 'toolchain' / 'bin' / tool
    if os.path.isfile(toolchain_tool_path):
        return str(toolchain_tool_path)
    return None

def try_find_global_tool(tool: str):
    return shutil.which(tool)

def try_find_external_tool(tool: str):
    return os.environ.get("NX_DECOMP_TOOLS_%s" % tool.upper().replace("-", "_"))

def find_tool(tool: str):
    if (tool_from_env := try_find_external_tool(tool)) is not None:
        return tool_from_env

    if (tool_from_toolchain := try_find_toolchain_tool(tool)) is not None:
        return tool_from_toolchain

    if (tool_from_binaries_repo := try_find_binaries_repo_tool(tool)) is not None:
        return tool_from_binaries_repo

    if (tool_from_path := try_find_global_tool(tool)) is not None:
        return tool_from_path

    print(f"Could not find tool: {tool} (maybe install it manually?)")
    exit(1)
