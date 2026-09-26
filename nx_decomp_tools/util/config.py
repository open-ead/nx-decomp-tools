from pathlib import Path
from typing import cast

DEFAULT_VERSION_TOKEN = "<default_version>"

def _get_nx_decomp_tools_path() -> Path:
    # we must be at tools/common of a downstream project,
    # NOT installed as a pip package.
    # If installed into a venv somewhere, that makes it impossible
    # to figure out the repo path, because the venv can be
    # anywhere on the system (i.e. might not be tools/.venv if downstream
    # doesn't use UV)

    root = Path(__file__).resolve().parent.parent.parent
    if root.name == "site-packages":
        raise RuntimeError("Cannot determine nx-decomp-tools path. \
nx-decomp-tools appears to be installed as a pip module in your current venv. \
This is currently not supported. You must add nx-decomp-tools as a workspace member.")

    # probe pyproject.toml to ensure downstream has put us in the right spot
    pyproject_toml = root / "pyproject.toml"
    try:
        txt = pyproject_toml.read_text()
        if "name = \"nx-decomp-tools\"" in txt:
            return root
    except:
        pass

    raise RuntimeError("Cannot determine nx-decomp-tools path. \
Make sure nx-decomp-tools is cloned at tools/common in your project, \
and included as a workspace member in pyproject.toml")

NX_DECOMP_TOOLS_PATH = _get_nx_decomp_tools_path()


def get_repo_root() -> Path:
    """Get the root of the downstream project"""
    
    # downstream projects are expected to include this repo
    # as a submodule at tools/common
    return NX_DECOMP_TOOLS_PATH.parent.parent


def get_data_root() -> Path:
    """Get the root of the downstream project's data directory"""
    return get_repo_root() / "data"


def get_build_root() -> Path:
    """Get the root of the downstream project's build directory"""
    return get_repo_root() / "build"


def get_toolchain_root() -> Path:
    """Get the root of the downstream project's toolchain directory"""
    return get_repo_root() / "toolchain"


def get_tools_root() -> Path:
    """Get the root of the downstream project's toolchain directory"""
    return get_repo_root() / "tools"


def get_config_path() -> Path:
    """Get config for shared tools in the downstream project"""
    return get_tools_root() / "config.toml"


cached_config = None
def get_config() -> dict:
    global cached_config
    if cached_config is not None:
        return cached_config
    import toml
    cached_config = toml.load(get_config_path())
    return cached_config


def get_default_version() -> str | None:
    return get_config().get("default_version")


def get_build_target() -> str:
    return get_config()["build_target"]


def get_versioned_data_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    return _get_versioned_path(get_data_root(), version)


def get_functions_csv_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    value: str = get_config()["functions_csv"]
    if version == DEFAULT_VERSION_TOKEN:
        version = get_default_version();
    if version is not None:
        value = value.replace("{version}", version)
    if "{version}" in value:
        raise RuntimeError("You should probably pass a --version parameter. If this error still shows up with the argument given, please contact the repo maintainers.")
    return get_repo_root() / value


def get_base_elf_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    return get_versioned_data_path() / "main.elf"


def get_uncompressed_nso_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    return get_versioned_data_path() / "main.uncompressed.nso"


def get_base_nso_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    return get_versioned_data_path() / "main.nso"


def get_decomp_elf_path(version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    return _get_versioned_path(get_build_root(), version) / get_build_target()


def _get_versioned_path(base: Path, version: str | None = DEFAULT_VERSION_TOKEN) -> Path:
    if version == DEFAULT_VERSION_TOKEN:
        version = get_default_version();
    if version is not None:
        return base / version
    return base
