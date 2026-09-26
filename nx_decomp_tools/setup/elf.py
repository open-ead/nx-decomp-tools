
from pathlib import Path
import subprocess

from nx_decomp_tools.util import warn, fail, find_tool, config

def convert_nso_to_elf(nso_path: Path, elf_out_path: str | Path = "", uncompressed_nso_out_path: str | Path | None = None):
    print(">>>> converting NSO to ELF...")
    if not elf_out_path:
        elf_out_path = str(config.get_base_elf_path())
    command = [find_tool("nx2elf"), str(nso_path), "--export-elf", elf_out_path];
    if uncompressed_nso_out_path is not None:
        command.append("--export-uncompressed")
        command.append(uncompressed_nso_out_path)
    subprocess.check_call(command)


def decompress_nso(nso_path: Path, dest_path: Path):
    warn("Using hactool to decompress the target NSO is deprecated, please use `_convert_nso_to_elf` instead")
    print(">>>> decompressing NSO...")
    subprocess.check_call([find_tool("hactool"), "-tnso",
                           "--uncompressed=" + str(dest_path), str(nso_path)])


def apply_xdelta3_patch(input: Path, patch: Path, dest: Path):
    print(">>>> applying patch...")
    try:
        subprocess.check_call(["xdelta3", "-d", "-s", str(input), str(patch), str(dest)])
    except FileNotFoundError:
        fail("error: install xdelta3 and try again")

