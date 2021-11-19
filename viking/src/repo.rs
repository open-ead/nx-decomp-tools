use anyhow::{bail, Result};
use lazy_static::lazy_static;
use std::path::PathBuf;


lazy_static! {
    pub static ref CONFIG: toml::Value = {
        let toml_path = get_repo_root().expect("Failed to get repo root").join("tools/config.toml");
        let toml = std::fs::read_to_string(toml_path.as_path()).expect("Failed to read config file").parse::<toml::Value>().expect("Failed to read TOML from config file");
        toml
    };
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

pub fn get_data_path(version: &Option<&str>) -> Result<PathBuf> {
    let data_dir_name = if let Some(v) = version {
        format!("data/{}", v)
    } else {
        "data".to_string()
    };

    Ok(get_repo_root()?.join(data_dir_name))
}
