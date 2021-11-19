from pathlib import Path
import toml


def get_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent

CONFIG = toml.load(get_repo_root() / "tools" / "config.toml")

def get_default_version() -> str:
    return CONFIG.get("default_version")

def get_functions_csv_path(version = None) -> Path:
    value = CONFIG["functions_csv"]
    if version is None:
        version = get_default_version()
    
    if version is not None:
        value = value.replace("{version}", version)
    
    if "{version}" in value:
        raise RuntimeError("You should probably pass a --version parameter. If this error still shows up with the argument given, please contact the repo maintainers.")

    return get_repo_root() / value

def get_base_elf(version = get_default_version()) -> Path:
    value = get_repo_root() / 'data'

    if version is not None:
        value /= version

    return value / 'main.elf'

def get_build_target() -> str:
    return CONFIG["build_target"]

def get_decomp_elf(version = get_default_version()) -> Path:
    value = get_repo_root() / 'build'

    if version is not None:
        value /= version

    return value / get_build_target()
