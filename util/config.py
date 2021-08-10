from pathlib import Path
import toml

def get_functions_csv_path() -> Path:
    return get_repo_root() / load_toml()["functions_csv"]

def get_decomp_elf() -> Path:
    return get_repo_root() / "build" / get_build_target()

def get_build_target() -> str:
    return load_toml()["build_target"]

def load_toml() -> toml:
    return toml.load(get_repo_root() / "tools" / "config.toml")

def get_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent
