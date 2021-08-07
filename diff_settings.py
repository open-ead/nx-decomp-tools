from pathlib import Path
import platform
import util.config

def get_tools_bin_dir():
    path = util.config.get_repo_root() / 'tools' / 'common' / 'nx-decomp-tools-binaries'
    system = platform.system()
    if system == "Linux":
        return str(path) + "/linux/"
    if system == "Darwin":
        return str(path) + "/macos/"
    return ""


def apply(config, args):
    config['arch'] = 'aarch64'
    config['baseimg'] = util.config.get_repo_root() / 'data/main.elf'
    config['myimg'] = util.config.get_decomp_elf()
    config['source_directories'] = ['src', 'lib']
    config['objdump_executable'] = get_tools_bin_dir() + 'aarch64-none-elf-objdump'

    for dir in ('build', 'build/nx64-release'):
        if (Path(dir) / 'build.ninja').is_file():
            config['make_command'] = ['ninja', '-C', dir]


def map_build_target(make_target: str):
    if make_target == util.config.get_decomp_elf():
        return util.config.get_build_target()

    # TODO: When support for directly diffing object files is added, this needs to strip
    # the build/ prefix from the object file targets.
    return make_target
