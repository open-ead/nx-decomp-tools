from pathlib import Path
import platform

from nx_decomp_tools.util import find_tool
from nx_decomp_tools.util import config as nx_config

def add_custom_arguments(parser):
    parser.add_argument('--version', dest='version', help='Specify which version should be recompiled on source changes')


def apply(config, args):
    root = nx_config.get_repo_root()

    version = None
    if isinstance(args, dict):
        version = args.get("version")
    else:
        try:
            version = args.version
        except AttributeError:
            pass
    if version is None:
        version = nx_config.get_default_version()

    config['arch'] = 'aarch64'
    config['baseimg'] = nx_config.get_base_elf_path(version)
    config['myimg'] = nx_config.get_decomp_elf_path(version)
    config['source_directories'] = [str(root / 'src'), str(root / 'lib')]
    config['objdump_executable'] = find_tool('llvm-objdump')
    # ill-suited to C++ projects (and too slow for large executables)
    config['show_line_numbers_default'] = False
    for dir in (root / 'build', root / 'build/nx64-release'):
        if (dir / 'build.ninja').is_file():
            config['make_command'] = ['ninja', '-C', str(dir)]

    if version is not None:
        dir = root / 'build' / version
        if (dir / 'build.ninja').is_file():
            config['make_command'] = ['ninja', '-C', str(dir)]


def map_build_target(make_target: str):
    if make_target == nx_config.get_decomp_elf_path():
        return nx_config.get_build_target()

    # TODO: When support for directly diffing object files is added, this needs to strip
    # the build/ prefix from the object file targets.
    return make_target
