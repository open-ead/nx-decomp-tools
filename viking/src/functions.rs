use crate::repo;
use anyhow::{bail, ensure, Context, Result};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Matching,
    NonMatchingMinor,
    NonMatchingMajor,
    NotDecompiled,
    Wip,
    Library,
}

impl Status {
    pub fn description(&self) -> &'static str {
        match &self {
            Status::Matching => "matching",
            Status::NonMatchingMinor => "non-matching (minor)",
            Status::NonMatchingMajor => "non-matching (major)",
            Status::NotDecompiled => "not decompiled",
            Status::Wip => "WIP",
            Status::Library => "library function",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Info {
    pub addr: u64,
    pub size: u32,
    pub name: String,
    pub status: Status,
}

impl Info {
    pub fn is_decompiled(&self) -> bool {
        !matches!(self.status, Status::NotDecompiled | Status::Library)
    }

    pub fn get_start(&self) -> u64 {
        self.addr | ADDRESS_BASE
    }

    pub fn get_end(&self) -> u64 {
        self.get_start() + self.size as u64
    }
}

pub const CSV_HEADER: &[&str] = &["Address", "Quality", "Size", "Name"];
pub const ADDRESS_BASE: u64 = 0x71_0000_0000;

fn parse_base_16(value: &str) -> Result<u64> {
    if let Some(stripped) = value.strip_prefix("0x") {
        Ok(u64::from_str_radix(stripped, 16)?)
    } else {
        Ok(u64::from_str_radix(value, 16)?)
    }
}

pub fn parse_address(value: &str) -> Result<u64> {
    Ok(parse_base_16(value)? - ADDRESS_BASE)
}

fn parse_function_csv_entry(record: &csv::StringRecord) -> Result<Info> {
    ensure!(record.len() == 4, "invalid record");

    let addr = parse_address(&record[0])?;
    let status_code = record[1].chars().next();
    let size = record[2].parse::<u32>()?;
    let decomp_name = record[3].to_string();

    let status = match status_code {
        Some('m') => Status::NonMatchingMinor,
        Some('M') => Status::NonMatchingMajor,
        Some('O') => Status::Matching,
        Some('U') => Status::NotDecompiled,
        Some('W') => Status::Wip,
        Some('L') => Status::Library,
        Some(code) => bail!("unexpected status code: {}", code),
        None => bail!("missing status code"),
    };

    Ok(Info {
        addr,
        size,
        name: decomp_name,
        status,
    })
}

fn check_for_duplicate_names(functions: &[Info], num_names: usize) -> Result<()> {
    let mut known_names = HashSet::with_capacity(num_names);
    let mut duplicates = Vec::new();

    for entry in functions {
        if entry.is_decompiled() && entry.name.is_empty() {
            bail!(
                "function at {:016x} is marked as O/M/m but has an empty name",
                entry.get_start()
            );
        }

        if !entry.name.is_empty() && !known_names.insert(&entry.name) {
            duplicates.push(&entry.name);
        }
    }

    if !duplicates.is_empty() {
        bail!("found duplicates: {:#?}", duplicates);
    }

    Ok(())
}

fn check_for_overlapping_functions(functions: &[Info]) -> Result<()> {
    for pair in functions.windows(2) {
        let first = &pair[0];
        let second = &pair[1];

        ensure!(
            first.get_start() < second.get_start() && first.get_end() <= second.get_start(),
            "overlapping functions: {:016x} - {:016x} and {:016x} - {:016x}",
            first.get_start(),
            first.get_end(),
            second.get_start(),
            second.get_end(),
        );
    }

    Ok(())
}

/// Returns a Vec of all functions that are listed in the specified CSV.
pub fn get_functions_for_path(csv_path: &Path) -> Result<Vec<Info>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .quoting(false)
        .from_path(csv_path)?;

    // We build the result array manually without using csv iterators for performance reasons.
    let mut result = Vec::with_capacity(110_000);
    let mut record = csv::StringRecord::new();
    let mut line_number = 1;
    let mut num_names = 0;
    if reader.read_record(&mut record)? {
        // Verify that the CSV has the correct format.
        ensure!(record.len() == 4, "invalid record; expected 4 fields");
        ensure!(record == *CSV_HEADER,
            "wrong CSV format; this program only works with the new function list format (added in commit 1d4c815fbae3)"
        );
        line_number += 1;
    }

    while reader.read_record(&mut record)? {
        let entry = parse_function_csv_entry(&record)
            .with_context(|| format!("failed to parse CSV record at line {}", line_number))?;

        if !entry.name.is_empty() {
            num_names += 1;
        }

        result.push(entry);
        line_number += 1;
    }

    check_for_duplicate_names(&result, num_names)?;
    check_for_overlapping_functions(&result)?;

    Ok(result)
}

pub fn write_functions_to_path(csv_path: &Path, functions: &[Info]) -> Result<()> {
    let mut writer = csv::Writer::from_path(csv_path)?;
    writer.write_record(CSV_HEADER)?;

    for function in functions {
        let addr = format!("0x{:016x}", function.get_start());
        let status = match function.status {
            Status::Matching => "O",
            Status::NonMatchingMinor => "m",
            Status::NonMatchingMajor => "M",
            Status::NotDecompiled => "U",
            Status::Wip => "W",
            Status::Library => "L",
        }
        .to_string();
        let size = format!("{:06}", function.size);
        let name = function.name.clone();
        writer.write_record(&[addr, status, size, name])?;
    }

    Ok(())
}

pub fn get_functions_csv_path(version: Option<&str>) -> PathBuf {
    let mut path = repo::get_repo_root().expect("Failed to get repo root");
    let config_functions_csv = repo::get_config().functions_csv.clone();
    let functions_csv = version
        .map(|s| config_functions_csv.replace("{version}", s))
        .unwrap_or(config_functions_csv);
    path.push(functions_csv);

    path
}

/// Returns a Vec of all known functions in the executable.
pub fn get_functions(version: Option<&str>) -> Result<Vec<Info>> {
    get_functions_for_path(get_functions_csv_path(version).as_path())
}

pub fn write_functions(functions: &[Info], version: Option<&str>) -> Result<()> {
    write_functions_to_path(get_functions_csv_path(version).as_path(), functions)
}

pub fn make_known_function_map(functions: &[Info]) -> FxHashMap<u64, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        if function.name.is_empty() {
            continue;
        }
        known_functions.insert(function.addr, function);
    }

    known_functions
}

pub fn make_known_function_name_map(functions: &[Info]) -> FxHashMap<&str, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        if function.name.is_empty() {
            continue;
        }
        known_functions.insert(function.name.as_str(), function);
    }

    known_functions
}

/// Demangle a C++ symbol.
pub fn demangle_str(name: &str) -> Result<String> {
    if !name.starts_with("_Z") {
        bail!("not an external mangled name");
    }

    let symbol = cpp_demangle::Symbol::new(name)?;
    let options = cpp_demangle::DemangleOptions::new();
    Ok(symbol.demangle(&options)?)
}

pub fn fuzzy_search<'a>(functions: &'a [Info], name: &str) -> Vec<&'a Info> {
    let exact_match = functions
        .par_iter()
        .find_first(|function| function.name == name);

    if let Some(exact_match) = exact_match {
        return vec![exact_match];
    }

    // Find all functions whose demangled name contains the specified string.
    // This is more expensive than a simple string comparison, so only do this after
    // we have failed to find an exact match.
    let mut candidates: Vec<&Info> = functions
        .par_iter()
        .filter(|function| {
            demangle_str(&function.name).is_ok_and(|demangled| demangled.contains(name))
                || function.name.contains(name)
        })
        .collect();

    candidates.sort_by_key(|info| info.addr);
    candidates
}
