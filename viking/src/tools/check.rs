use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use capstone as cs;
use capstone::arch::BuildsCapstone;
use colored::*;
use goblin::elf::sym::STT_FUNC;
use itertools::Itertools;
use lexopt::prelude::*;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use viking::checks::FunctionChecker;
use viking::checks::Mismatch;
use viking::elf;
use viking::functions;
use viking::functions::Status;
use viking::repo;
use viking::ui;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

enum CheckResult {
    // If a function does not match, but is marked as such, return this error to show an appropriate exit message.
    MismatchError,
    // If a function does match, but is marked as mismatching, return this warning to indicate this and update it if invoked with `--update-matching`.
    MatchWarn,
    // Check result matches the expected value listed in the function table.
    Ok,
}

fn check_function(
    checker: &FunctionChecker,
    cs: &mut capstone::Capstone,
    orig_elf: &elf::OwnedElf,
    decomp_elf: &elf::OwnedElf,
    decomp_symtab: &elf::SymbolTableByName,
    function: &functions::Info,
) -> Result<CheckResult> {
    let name = function.name.as_str();
    let decomp_fn = elf::get_function_by_name(decomp_elf, decomp_symtab, name);

    match function.status {
        Status::NotDecompiled if decomp_fn.is_err() => return Ok(CheckResult::Ok),
        Status::Library => return Ok(CheckResult::Ok),
        _ => (),
    }

    if decomp_fn.is_err() {
        let error = decomp_fn.err().unwrap();
        ui::print_warning(&format!(
            "couldn't check {}: {}",
            ui::format_symbol_name(name),
            error.to_string().dimmed(),
        ));
        return Ok(CheckResult::Ok);
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
                return Ok(CheckResult::MismatchError);
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
                return Ok(CheckResult::MatchWarn);
            }
        }

        Status::Library => unreachable!(),
    };

    Ok(CheckResult::Ok)
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
    update_matching: bool,
    version: &Option<&str>,
) -> Result<()> {
    let failed = AtomicBool::new(false);
    let matching_functions: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());

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
            if matches!(ok, CheckResult::MismatchError) {
                failed.store(true, std::sync::atomic::Ordering::Relaxed);
            } else if update_matching && matches!(ok, CheckResult::MatchWarn) {
                matching_functions.lock().unwrap().insert(function.addr);
            }

            Ok(())
        })
    })?;

    if update_matching {
        let functions_to_update = matching_functions.lock().unwrap();
        let mut new_functions = functions.iter().cloned().collect_vec();
        new_functions
            .iter_mut()
            .filter(|info| functions_to_update.contains(&info.addr))
            .for_each(|info| info.status = functions::Status::Matching);

        functions::write_functions(&new_functions, version)?;
    }

    if failed.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("found at least one error");
    } else {
        Ok(())
    }
}

fn resolve_unknown_fn_interactively(
    ambiguous_name: &str,
    decomp_symtab: &elf::SymbolTableByName,
    functions: &[functions::Info],
) -> Result<String> {
    let fail = || -> Result<String> {
        bail!("unknown function: {}", ambiguous_name);
    };

    let mut candidates: Vec<_> = decomp_symtab
        .par_iter()
        .filter(|(&name, &sym)| {
            sym.st_type() == STT_FUNC
                && functions::demangle_str(name)
                    .unwrap_or_else(|_| "".to_string())
                    .contains(ambiguous_name)
        })
        .collect();

    // Sort candidates by their name, then deduplicate them based on the address.
    // This ensures that e.g. C1 symbols take precedence over C2 symbols (if both are present).
    candidates.sort_by_key(|(&name, _)| name);
    candidates.sort_by_key(|(_, &sym)| sym.st_value);
    candidates.dedup_by_key(|(_, &sym)| sym.st_value);

    // Build a set of functions that have already been decompiled and listed,
    // so we don't suggest them to the user again.
    let decompiled_functions: HashSet<&str> = functions
        .iter()
        .filter(|info| info.is_decompiled())
        .map(|info| info.name.as_str())
        .collect();
    candidates.retain(|(&name, _)| !decompiled_functions.contains(name));

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

fn rediff_function_after_differ(
    functions: &[functions::Info],
    orig_fn: &elf::Function,
    name: &str,
    previous_check_result: &Option<Mismatch>,
    version: &Option<&str>,
) -> Result<Option<Mismatch>> {
    // Reload the decomp ELF because it may have been modified.
    //
    // This can typically happen if the differ was invoked with -mw (auto rebuild);
    // the user could have managed to match a function that used to be non-matching
    // back when the differ was launched.
    let decomp_elf = elf::load_decomp_elf(version).context("failed to reload decomp ELF")?;

    // Also reload the symbol table from the new ELF.
    let decomp_symtab = elf::make_symbol_map_by_name(&decomp_elf)?;
    let decomp_glob_data_table = elf::build_glob_data_table(&decomp_elf)?;

    // And grab the possibly updated function code.
    // Note that the original function doesn't need to be reloaded.
    let decomp_fn =
        elf::get_function_by_name(&decomp_elf, &decomp_symtab, name).with_context(|| {
            format!(
                "failed to reload decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    // Invoke the checker again.
    let checker = FunctionChecker::new(
        orig_fn.owner_elf,
        &decomp_elf,
        &decomp_symtab,
        decomp_glob_data_table,
        functions,
        version,
    )?;

    let maybe_mismatch = checker
        .check(&mut make_cs()?, orig_fn, &decomp_fn)
        .with_context(|| format!("re-checking {}", name))?;

    if previous_check_result.is_some() == maybe_mismatch.is_some() {
        if let Some(mismatch) = &maybe_mismatch {
            eprintln!("{}\n{}", "still mismatching".red().bold(), &mismatch);
        } else {
            eprintln!("{}", "still OK".green().bold());
        }
    } else {
        // Matching status has changed.
        if let Some(mismatch) = &maybe_mismatch {
            eprintln!("{}\n{}", "mismatching now".red().bold(), &mismatch);
        } else {
            eprintln!("{}", "OK now".green().bold());
        }
    }

    Ok(maybe_mismatch)
}

fn check_single(
    functions: &[functions::Info],
    checker: &FunctionChecker,
    orig_elf: &elf::OwnedElf,
    decomp_elf: &elf::OwnedElf,
    decomp_symtab: &elf::SymbolTableByName,
    args: &[String],
    always_diff: bool,
    version: &Option<&str>,
    fn_to_check: &str,
) -> Result<()> {
    let function = functions::find_function_fuzzy(functions, fn_to_check)
        .with_context(|| format!("unknown function: {}", ui::format_symbol_name(fn_to_check)))?;
    let mut name = function.name.as_str();

    eprintln!("{}", ui::format_symbol_name(name).bold());

    if matches!(function.status, Status::Library) {
        bail!("L functions should not be decompiled");
    }

    let resolved_name;
    let name_was_ambiguous;
    if !decomp_symtab.contains_key(name) {
        resolved_name = resolve_unknown_fn_interactively(name, decomp_symtab, functions)?;
        name = &resolved_name;
        name_was_ambiguous = true;
    } else {
        name_was_ambiguous = false;
    }
    let name = name;

    let decomp_fn =
        elf::get_function_by_name(decomp_elf, decomp_symtab, name).with_context(|| {
            format!(
                "failed to get decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    let orig_fn = elf::get_function(orig_elf, function.addr, function.size as u64)?;

    let mut maybe_mismatch = checker
        .check(&mut make_cs()?, &orig_fn, &decomp_fn)
        .with_context(|| format!("checking {}", name))?;

    let mut should_show_diff = always_diff;

    if let Some(mismatch) = &maybe_mismatch {
        eprintln!("{}\n{}", "mismatch".red().bold(), &mismatch);
        should_show_diff = true;
    } else {
        eprintln!("{}", "OK".green().bold());
    }

    if should_show_diff {
        let mut diff_args: Vec<String> = args.to_owned();

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

        maybe_mismatch =
            rediff_function_after_differ(functions, &orig_fn, name, &maybe_mismatch, version)
                .context("failed to rediff")?;
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

struct Args {
    function: Option<String>,
    version: Option<String>,
    always_diff: bool,
    update_matching: bool,
    other_args: Vec<String>,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut function = None;
    let mut version = repo::CONFIG.get("default_version").map(|s| s.to_string());
    let mut always_diff = false;
    let mut update_matching = false;
    let mut other_args: Vec<String> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => {
                version = Some(parser.value()?.into_string()?);
            }
            Long("update-matching") => {
                update_matching = true;
            }
            Long("always-diff") => {
                always_diff = true;
            }

            Value(other_val) if function.is_none() => {
                function = Some(other_val.into_string()?);
            }
            Value(other_val) if function.is_some() => {
                other_args.push(other_val.into_string()?);
            }
            Long(other_long) => {
                other_args.push(format!("--{}", other_long));
                let opt = parser.optional_value();
                if let Some(o) = opt {
                    other_args.push(o.into_string()?);
                }
            }
            Short(other_short) => {
                other_args.push(format!("-{}", other_short));
            }

            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        function,
        version,
        always_diff,
        update_matching,
        other_args,
    })
}

fn main() -> Result<()> {
    ui::init_prompt_settings();

    let args = parse_args()?;

    let version = args.version.as_deref();

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

    if let Some(func) = &args.function {
        // Single function mode.
        check_single(
            &functions,
            &checker,
            &orig_elf,
            &decomp_elf,
            &decomp_symtab,
            &args.other_args,
            args.always_diff,
            &version,
            func,
        )?;
    } else {
        // Normal check mode.
        check_all(
            &functions,
            &checker,
            &orig_elf,
            &decomp_elf,
            &decomp_symtab,
            args.update_matching,
            &version,
        )?;
    }

    Ok(())
}
