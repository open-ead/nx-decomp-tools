use anyhow::{bail, Result};
use lazy_static::lazy_static;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
pub struct Config {
    pub build_target: String,
    pub functions_csv: String,
    pub default_version: Option<String>,
    pub decomp_me: Option<ConfigDecompMe>,
}

#[derive(serde::Deserialize)]
pub struct ConfigDecompMe {
    /// Must specify either ( Compiler and Flags ) or ( Preset Id ).

    /// Name of the compiler used to compile the code
    pub compiler_name: Option<String>,

    /// Compilation flags that are used for creating scratches.
    pub default_compile_flags: Option<String>,
    /// Toggle overriding of default flags (above) with database flags. (True by default)
    pub override_compile_flags: Option<bool>,

    /// Preset ID used for categorizing. Requires registering preset with compiler and flags.
    pub preset_id: Option<String>,
}

lazy_static! {
    static ref CONFIG: Config = {
        let toml_path = get_repo_root()
            .expect("failed to get repo root")
            .join("tools/config.toml");
        let raw = std::fs::read_to_string(toml_path.as_path()).expect("failed to read config file");
        toml::from_str(&raw).expect("failed to parse config file")
    };
}

pub fn get_config() -> &'static Config {
    &CONFIG
}

pub fn get_repo_root() -> Result<PathBuf> {
    let current_dir = std::env::current_dir()?;
    let mut dir = current_dir.as_path();

    loop {
        if ["data", "src"].iter().all(|name| dir.join(name).is_dir()) {
            return Ok(dir.to_path_buf());
        }

        match dir.parent() {
            None => {
                bail!("failed to find repo root -- run this program inside the repo");
            }
            Some(parent) => dir = parent,
        };
    }
}

pub fn get_tools_path() -> Result<PathBuf> {
    Ok(get_repo_root()?.join("tools/common"))
}

fn get_version_specific_dir_path(dir_name: &str, version: Option<&str>) -> Result<PathBuf> {
    let dir_name = if let Some(v) = version {
        format!("{dir_name}/{v}")
    } else {
        dir_name.to_string()
    };

    Ok(get_repo_root()?.join(dir_name))
}

pub fn get_data_path(version: Option<&str>) -> Result<PathBuf> {
    get_version_specific_dir_path("data", version)
}

pub fn get_build_path(version: Option<&str>) -> Result<PathBuf> {
    get_version_specific_dir_path("build", version)
}
