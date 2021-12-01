use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use capstone as cs;
use capstone::arch::BuildsCapstone;
use colored::*;
use itertools::Itertools;
use rayon::prelude::*;
use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use viking::checks::FunctionChecker;
use viking::elf;
use viking::functions;
use viking::functions::Status;
use viking::repo;
use viking::ui;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Returns false if the program should exit with a failure code at the end.
fn check_function(
    checker: &FunctionChecker,
    cs: &mut capstone::Capstone,
    orig_elf: &elf::OwnedElf,
    decomp_elf: &elf::OwnedElf,
    decomp_symtab: &elf::SymbolTableByName,
    function: &functions::Info,
) -> Result<bool> {
    let name = function.name.as_str();
    let decomp_fn = elf::get_function_by_name(decomp_elf, decomp_symtab, name);

    match function.status {
        Status::NotDecompiled if decomp_fn.is_err() => return Ok(true),
        Status::Library => return Ok(true),
        _ => (),
    }

    if decomp_fn.is_err() {
        let error = decomp_fn.err().unwrap();
        ui::print_warning(&format!(
            "couldn't check {}: {}",
            ui::format_symbol_name(name),
            error.to_string().dimmed(),
        ));
        return Ok(true);
    }

    let decomp_fn = decomp_fn.unwrap();

    let get_orig_fn = || {
        elf::get_function(orig_elf, function.addr, function.size as u64).with_context(|| {
            format!(
                "failed to get function {} ({}) from the original executable",
                name,
                ui::format_address(function.addr),
            )
        })
    };

    match function.status {
        Status::Matching => {
            let orig_fn = get_orig_fn()?;

            let result = checker
                .check(cs, &orig_fn, &decomp_fn)
                .with_context(|| format!("checking {}", name))?;

            if let Some(mismatch) = result {
                let stderr = std::io::stderr();
                let mut lock = stderr.lock();
                ui::print_error_ex(
                    &mut lock,
                    &format!(
                        "function {} is marked as matching but does not match",
                        ui::format_symbol_name(name),
                    ),
                );
                ui::print_detail_ex(&mut lock, &format!("{}", mismatch));
                return Ok(false);
            }
        }

        Status::NotDecompiled
        | Status::NonMatchingMinor
        | Status::NonMatchingMajor
        | Status::Wip => {
            let orig_fn = get_orig_fn()?;

            let result = checker
                .check(cs, &orig_fn, &decomp_fn)
                .with_context(|| format!("checking {}", name))?;

            if result.is_none() {
                ui::print_note(&format!(
                    "function {} is marked as {} but matches",
                    ui::format_symbol_name(name),
                    function.status.description(),
                ));
            }
        }

        Status::Library => unreachable!(),
    };

    Ok(true)
}

#[cold]
#[inline(never)]
fn make_cs() -> Result<cs::Capstone> {
    cs::Capstone::new()
        .arm64()
        .mode(cs::arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .or_else(viking::capstone_utils::translate_cs_error)
}

thread_local! {
    static CAPSTONE: RefCell<cs::Capstone> = RefCell::new(make_cs().unwrap());
}

fn check_all(
    functions: &[functions::Info],
    checker: &FunctionChecker,
    orig_elf: &elf::OwnedElf,
    decomp_elf: &elf::OwnedElf,
    decomp_symtab: &elf::SymbolTableByName,
) -> Result<()> {
    let failed = AtomicBool::new(false);

    functions.par_iter().try_for_each(|function| {
        CAPSTONE.with(|cs| -> Result<()> {
            let mut cs = cs.borrow_mut();
            let ok = check_function(
                checker,
                &mut cs,
                orig_elf,
                decomp_elf,
                decomp_symtab,
                function,
            )?;
            if !ok {
                failed.store(true, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(())
        })
    })?;

    if failed.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("found at least one error");
    } else {
        Ok(())
    }
}

fn get_function_to_check_from_args(args: &[String]) -> Result<String> {
    let mut maybe_fn_to_check: Vec<String> = args
        .iter()
        .filter(|s| !s.starts_with('-'))
        .cloned()
        .collect();

    ensure!(
        maybe_fn_to_check.len() == 1,
        "expected only one function name (one argument that isn't prefixed with '-')"
    );

    Ok(maybe_fn_to_check.remove(0))
}

fn get_version_from_args_or_config(args: &[String]) -> Result<Option<&str>> {
    let mut iter = args.iter().filter_map(|s| s.strip_prefix("--version="));
    match (iter.next(), iter.next()) {
        (Some(_), Some(_)) => bail!("expected only one version number ('--version=XXX')"),
        (None, None) => Ok(repo::CONFIG
            .get("default_version")
            .map(|s| s.as_str())
            .unwrap_or(None)),
        (Some(s), None) => Ok(Some(s)),

        (None, Some(_)) => unreachable!(),
    }
}

fn resolve_unknown_fn_interactively(
    ambiguous_name: &str,
    decomp_symtab: &elf::SymbolTableByName,
) -> Result<String> {
    let fail = || -> Result<String> {
        bail!("unknown function: {}", ambiguous_name);
    };

    let mut candidates: Vec<_> = decomp_symtab
        .par_iter()
        .filter(|(&name, _)| {
            functions::demangle_str(name)
                .unwrap_or_else(|_| "".to_string())
                .contains(ambiguous_name)
        })
        .collect();

    candidates.sort_by_key(|(_, &sym)| sym.st_value);
    candidates.dedup_by_key(|(_, &sym)| sym.st_value);

    if candidates.is_empty() {
        return fail();
    }

    ui::clear_terminal();

    if candidates.len() == 1 {
        let prompt = format!(
            "{} is ambiguous; did you mean: {}",
            ambiguous_name,
            ui::format_symbol_name(candidates[0].0),
        );

        let confirmed = inquire::Confirm::new(&prompt).with_default(true).prompt()?;

        if !confirmed {
            return fail();
        }

        Ok(candidates[0].0.to_string())
    } else {
        let prompt = format!("{} is ambiguous; did you mean:", ambiguous_name);
        let options = candidates
            .iter()
            .map(|(&name, _)| ui::format_symbol_name(name))
            .collect_vec();

        let selection = inquire::Select::new(&prompt, options)
            .with_starting_cursor(0)
            .raw_prompt()?
            .index;

        Ok(candidates[selection].0.to_string())
    }
}

fn check_single(
    functions: &[functions::Info],
    checker: &FunctionChecker,
    orig_elf: &elf::OwnedElf,
    decomp_elf: &elf::OwnedElf,
    decomp_symtab: &elf::SymbolTableByName,
    args: &[String],
    version: &Option<&str>,
) -> Result<()> {
    let fn_to_check = get_function_to_check_from_args(args)?;
    let function = functions::find_function_fuzzy(functions, &fn_to_check)
        .with_context(|| format!("unknown function: {}", ui::format_symbol_name(&fn_to_check)))?;
    let mut name = function.name.as_str();

    eprintln!("{}", ui::format_symbol_name(name).bold());

    if matches!(function.status, Status::Library) {
        bail!("L functions should not be decompiled");
    }

    let resolved_name;
    let name_was_ambiguous;
    if !decomp_symtab.contains_key(name) {
        resolved_name = resolve_unknown_fn_interactively(name, decomp_symtab)?;
        name = &resolved_name;
        name_was_ambiguous = true;
    } else {
        name_was_ambiguous = false;
    }

    let decomp_fn =
        elf::get_function_by_name(decomp_elf, decomp_symtab, name).with_context(|| {
            format!(
                "failed to get decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    let orig_fn = elf::get_function(orig_elf, function.addr, function.size as u64)?;

    let maybe_mismatch = checker
        .check(&mut make_cs()?, &orig_fn, &decomp_fn)
        .with_context(|| format!("checking {}", name))?;

    let mut should_show_diff = args.iter().any(|s| s.as_str() == "--always-diff");

    if let Some(mismatch) = &maybe_mismatch {
        eprintln!("{}\n{}", "mismatch".red().bold(), &mismatch);
        should_show_diff = true;
    } else {
        eprintln!("{}", "OK".green().bold());
    }

    if should_show_diff {
        let mut diff_args: Vec<String> = args
            .iter()
            .filter(|s| {
                s.as_str() != fn_to_check
                    && s.as_str() != "--always-diff"
                    && !s.as_str().starts_with("--version=")
            })
            .cloned()
            .collect();

        let differ_path = repo::get_tools_path()?.join("asm-differ").join("diff.py");

        if version.is_some() {
            diff_args.push("--version".to_owned());
            diff_args.push(version.unwrap().to_owned());
        }

        std::process::Command::new(&differ_path)
            .current_dir(repo::get_tools_path()?)
            .arg("-I")
            .arg("-e")
            .arg(name)
            .arg(format!("0x{:016x}", function.addr))
            .arg(format!("0x{:016x}", function.addr + function.size as u64))
            .args(diff_args)
            .status()
            .with_context(|| format!("failed to launch asm-differ: {:?}", &differ_path))?;
    }

    let new_status = match maybe_mismatch {
        None => Status::Matching,
        Some(_) => Status::Wip,
    };

    // Update the function entry if needed.
    let status_changed = function.status != new_status;
    if status_changed || name_was_ambiguous {
        if status_changed {
            ui::print_note(&format!(
                "changing status from {:?} to {:?}",
                function.status, new_status
            ));
        }

        let mut new_functions = functions.iter().cloned().collect_vec();
        let new_entry = new_functions
            .iter_mut()
            .find(|info| info.addr == function.addr)
            .unwrap();
        new_entry.status = new_status;
        new_entry.name = name.to_string();
        functions::write_functions(&new_functions, version)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    ui::init_prompt_settings();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let version = get_version_from_args_or_config(&args)?;

    let orig_elf = elf::load_orig_elf(&version).context("failed to load original ELF")?;
    let decomp_elf = elf::load_decomp_elf(&version).context("failed to load decomp ELF")?;

    // Load these in parallel.
    let mut decomp_symtab = None;
    let mut decomp_glob_data_table = None;
    let mut functions = None;

    rayon::scope(|s| {
        s.spawn(|_| decomp_symtab = Some(elf::make_symbol_map_by_name(&decomp_elf)));
        s.spawn(|_| decomp_glob_data_table = Some(elf::build_glob_data_table(&decomp_elf)));
        s.spawn(|_| functions = Some(functions::get_functions(&version)));
    });

    let decomp_symtab = decomp_symtab
        .unwrap()
        .context("failed to make symbol map")?;

    let decomp_glob_data_table = decomp_glob_data_table
        .unwrap()
        .context("failed to make global data table")?;

    let functions = functions.unwrap().context("failed to load function CSV")?;

    let checker = FunctionChecker::new(
        &orig_elf,
        &decomp_elf,
        &decomp_symtab,
        decomp_glob_data_table,
        &functions,
        &version,
    )
    .context("failed to construct FunctionChecker")?;

    let mut single_diff = !args.is_empty();
    if version.is_some() {
        single_diff = args.len() >= 2;
    }

    if single_diff {
        // Single function mode.
        check_single(
            &functions,
            &checker,
            &orig_elf,
            &decomp_elf,
            &decomp_symtab,
            &args,
            &version,
        )?;
    } else {
        // Normal check mode.
        check_all(&functions, &checker, &orig_elf, &decomp_elf, &decomp_symtab)?;
    }

    Ok(())
}
