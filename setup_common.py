import os
import platform
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).parent.parent.parent
TARGET_PATH = ROOT / "data" / "main.nso"
TARGET_ELF_PATH = ROOT / "data" / "main.elf"


def fail(error: str):
    print(">>> " + error)
    sys.exit(1)


def _get_tool_binary_path():
    base = ROOT / "tools" / "common" / "nx-decomp-tools-binaries"
    system = platform.system()
    if system == "Linux":
        return str(base / "linux") + "/"
    if system == "Darwin":
        return str(base / "macos") + "/"
    return ""


def _convert_nso_to_elf(nso_path: Path):
    print(">>>> converting NSO to ELF...")
    binpath = _get_tool_binary_path()
    subprocess.check_call([binpath + "nx2elf", str(nso_path)])


def _decompress_nso(nso_path: Path, dest_path: Path):
    print(">>>> decompressing NSO...")
    binpath = _get_tool_binary_path()
    subprocess.check_call([binpath + "hactool", "-tnso",
                           "--uncompressed=" + str(dest_path), str(nso_path)])

def install_viking():
    print(">>>> installing viking (tools/check)")
    src_path = ROOT / "tools" / "common" / "viking"
    install_path = ROOT / "tools"
    try:
        subprocess.check_call(["cargo", "build", "--manifest-path",src_path/"Cargo.toml", "--release"])
        (src_path / "target" / "release" / "check").rename(install_path / "check")
    except FileNotFoundError:
        print(sys.exc_info()[0])
        fail("error: install cargo (rust) and try again")

def _apply_xdelta3_patch(input: Path, patch: Path, dest: Path):
    print(">>>> applying patch...")
    try:
        subprocess.check_call(["xdelta3", "-d", "-s", str(input), str(patch), str(dest)])
    except FileNotFoundError:
        fail("error: install xdelta3 and try again")

def set_up_compiler(version):
    compiler_dir = ROOT / "toolchain" / ("clang-"+version)
    if compiler_dir.is_dir():
        print(">>> clang is already set up: nothing to do")
        return

    system = platform.system()
    machine = platform.machine()

    if(version == "4.0.1"):
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/4.0.1/clang+llvm-4.0.1-x86_64-linux-gnu-Fedora-25.tar.xz",
                "dir_name": "clang+llvm-4.0.1-x86_64-linux-gnu-Fedora-25",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/4.0.1/clang+llvm-4.0.1-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-4.0.1-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://releases.llvm.org/4.0.1/clang+llvm-4.0.1-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-4.0.1-x86_64-apple-darwin",
            },
            ("Darwin", "aarch64"): {
                "url": "https://releases.llvm.org/4.0.1/clang+llvm-4.0.1-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-4.0.1-x86_64-apple-darwin",
            },
        }

    build_info = builds.get((system, machine))
    if build_info is None:
        fail(
            f"unknown platform: {platform.platform()} - {version} (please report if you are on Linux and macOS)")

    url: str = build_info["url"]
    dir_name: str = build_info["dir_name"]

    print(f">>> downloading Clang from {url}...")
    with tempfile.TemporaryDirectory() as tmpdir:
        path = tmpdir + "/" + url.split("/")[-1]
        urllib.request.urlretrieve(url, path)

        print(f">>> extracting Clang...")
        with tarfile.open(path) as f:
            f.extractall(compiler_dir.parent)
            (compiler_dir.parent / dir_name).rename(compiler_dir)

    print(">>> successfully set up Clang")
