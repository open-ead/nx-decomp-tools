import os
import shutil
import platform
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from common.util import config, tools

ROOT = Path(__file__).parent.parent.parent

def get_target_path(version = config.get_default_version()):
    return config.get_versioned_data_path(version) / "main.nso"

def get_target_elf_path(version = config.get_default_version()):
    return config.get_versioned_data_path(version) / "main.elf"


def fail(error: str):
    print(">>> " + error)
    sys.exit(1)

def _convert_nso_to_elf(nso_path: Path):
    print(">>>> converting NSO to ELF...")
    subprocess.check_call([tools.find_tool("nx2elf"), str(nso_path)])


def _decompress_nso(nso_path: Path, dest_path: Path):
    print(">>>> decompressing NSO...")
    subprocess.check_call([tools.find_tool("hactool"), "-tnso",
                           "--uncompressed=" + str(dest_path), str(nso_path)])

def install_viking():
    src_path = ROOT / "tools" / "common" / "viking"
    install_path = ROOT / "tools"
    tool_names = ["check", "listsym", "decompme"]

    print(">>>> installing viking (tools/check)")

    try:
        subprocess.check_call(["cargo", "build", "--manifest-path", src_path / "Cargo.toml", "--release"])
        for tool in tool_names:
            (src_path / "target" / "release" / tool).rename(install_path / tool)
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

    if version == "3.9.1":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/3.9.1/clang+llvm-3.9.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz",
                "dir_name": "clang+llvm-3.9.1-x86_64-linux-gnu-ubuntu-16.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/3.9.1/clang+llvm-3.9.1-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-3.9.1-aarch64-linux-gnu",
            }
        }
    elif version == "4.0.1":
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
                "dir_name": "clang+llvm-4.0.1-x86_64-apple-macosx10.9.0",
            },
            ("Darwin", "arm64"): {
                "url": "https://releases.llvm.org/4.0.1/clang+llvm-4.0.1-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-4.0.1-x86_64-apple-macosx10.9.0",
            },
        }
    elif version == "5.0.1":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/5.0.1/clang+llvm-5.0.1-x86_64-linux-gnu-Fedora27.tar.xz",
                "dir_name": "clang+llvm-5.0.1-x86_64-linux-gnu-Fedora27",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/5.0.1/clang+llvm-5.0.1-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-5.0.1-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://releases.llvm.org/5.0.1/clang+llvm-5.0.1-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-5.0.1-x86_64-apple-macosx10.9.0",
            },
            ("Darwin", "arm64"): {
                "url": "https://releases.llvm.org/5.0.1/clang+llvm-5.0.1-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-5.0.1-x86_64-apple-macosx10.9.0",
            },
        }
    elif version == "7.0.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/7.0.0/clang+llvm-7.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz",
                "dir_name": "clang+llvm-7.0.0-x86_64-linux-gnu-ubuntu-16.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/7.0.0/clang+llvm-7.0.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-7.1.0-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://releases.llvm.org/7.0.0/clang+llvm-7.0.0-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-7.0.0-x86_64-apple-darwin",
            }
        }
    elif version == "7.1.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz",
                "dir_name": "clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/clang+llvm-7.1.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-7.1.0-aarch64-linux-gnu",
            }
        }
    elif version == "8.0.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/8.0.0/clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz",
                "dir_name": "clang+llvm-8.0.0-x86_64-linux-gnu-ubuntu-18.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/8.0.0/clang+llvm-8.0.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-8.0.0-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://releases.llvm.org/8.0.0/clang+llvm-8.0.0-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-8.0.0-x86_64-apple-darwin",
            }
        }
    elif version == "9.0.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz",
                "dir_name": "clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-9.0.0-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-darwin-apple.tar.xz",
                "dir_name": "clang+llvm-9.0.0-x86_64-apple-darwin",
            }
        }
    elif version == "10.0.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz",
                "dir_name": "clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-10.0.0-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-10.0.0-x86_64-apple-darwin",
            }
        }
    elif version == "11.0.0":
        builds = {
            # Linux
            ("Linux", "x86_64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/clang+llvm-11.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz",
                "dir_name": "clang+llvm-11.0.0-x86_64-linux-gnu-ubuntu-20.04",
            },
            ("Linux", "aarch64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/clang+llvm-11.0.0-aarch64-linux-gnu.tar.xz",
                "dir_name": "clang+llvm-11.0.0-aarch64-linux-gnu",
            },

            # macOS
            ("Darwin", "x86_64"): {
                "url": "https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/clang+llvm-11.0.0-x86_64-apple-darwin.tar.xz",
                "dir_name": "clang+llvm-11.0.0-x86_64-apple-darwin",
            }
        }
    else:
        builds = {}

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
