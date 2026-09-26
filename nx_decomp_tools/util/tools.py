from .config import get_toolchain_root
import platform
import os
import shutil

def find_tool(tool: str):
    if (tool_from_env := _try_find_external_tool(tool)) is not None:
        return tool_from_env

    if (tool_from_toolchain := _try_find_toolchain_tool(tool)) is not None:
        return tool_from_toolchain

    if (tool_from_binaries_repo := _try_find_binaries_repo_tool(tool)) is not None:
        return tool_from_binaries_repo

    if (tool_from_path := _try_find_global_tool(tool)) is not None:
        return tool_from_path

    raise RuntimeError(f"Could not find tool: {tool} (maybe install it manually?)")

def _try_find_binaries_repo_tool(tool: str) -> str | None:
    binaries_repo_path = get_toolchain_root() / 'nx-decomp-tools-binaries'
    system = platform.system()
    tool_path = str(binaries_repo_path)
    if system == "Linux":
        tool_path += "/linux/"
    elif system == "Darwin":
        tool_path += "/macos/"
    tool_path += tool
    if os.path.isfile(tool_path):
        return tool_path
    return None

def _try_find_toolchain_tool(tool: str) -> str | None:
    toolchain_tool_path = get_toolchain_root() / 'bin' / tool
    if os.path.isfile(toolchain_tool_path):
        return str(toolchain_tool_path)
    return None

def _try_find_global_tool(tool: str) -> str | None:
    return shutil.which(tool)

def _try_find_external_tool(tool: str) -> str | None:
    return os.environ.get("NX_DECOMP_TOOLS_%s" % tool.upper().replace("-", "_"))

