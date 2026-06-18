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
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic;
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

#[derive(Default)]
struct Args {
    function: Option<String>,
    version: Option<String>,
    always_diff: bool,
    warnings_as_errors: bool,
    check_mismatch_comments: bool,
    print_help: bool,
    other_args: Vec<String>,
}

impl Args {
    fn get_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

fn main() -> Result<()> {
    ui::init_prompt_settings();

    let args = parse_args()?;

    if args.print_help {
        print_help()?;
        return Ok(());
    }

    let version = args.get_version();

    let orig_elf = elf::load_orig_elf(version).context("failed to load original ELF")?;
    let decomp_elf = elf::load_decomp_elf(version).context("failed to load decomp ELF")?;

    // Load these in parallel.
    let mut decomp_symtab = None;
    let mut decomp_glob_data_table = None;
    let mut functions = None;
    let mut plt_functions = None;
    let mut orig_dynsym = None;
    let mut decomp_dynsym = None;

    rayon::scope(|s| {
        s.spawn(|_| decomp_symtab = Some(elf::make_symbol_map_by_name(&decomp_elf)));
        s.spawn(|_| decomp_glob_data_table = Some(elf::build_glob_data_table(&decomp_elf)));
        s.spawn(|_| functions = Some(functions::get_functions(version)));
        s.spawn(|_| plt_functions = Some(elf::get_plt_functions(&orig_elf)));
        s.spawn(|_| orig_dynsym = Some(elf::make_dynsym_map_by_name(&orig_elf)));
        s.spawn(|_| decomp_dynsym = Some(elf::make_dynsym_map_by_name(&decomp_elf)));
    });

    let decomp_symtab = decomp_symtab
        .unwrap()
        .context("failed to make symbol map")?;
    let decomp_glob_data_table = decomp_glob_data_table
        .unwrap()
        .context("failed to make global data table")?;

    let functions = functions.unwrap().context("failed to load function CSV")?;
    let plt_functions = plt_functions
        .unwrap()
        .context("failed to load plt functions")?;
    
    let orig_dynsym = orig_dynsym
        .unwrap()
        .context("failed to make original ELF dynsym map")?;

    let decomp_dynsym = decomp_dynsym
        .unwrap()
        .context("failed to make decomp ELF dynsym map")?;

    let all_functions = vec![functions.clone(), plt_functions].concat();

    let checker = FunctionChecker::new(
        &orig_elf,
        &decomp_elf,
        &decomp_symtab,
        decomp_glob_data_table,
        &all_functions,
        version,
    )
    .context("failed to construct FunctionChecker")?;

    if let Some(func) = &args.function {
        check_single(&checker, &functions, &all_functions, func, &args)?;
        return Ok(())

    }

    check_all(&checker, &all_functions, &args)?;

    if repo::get_config().check_symbols.unwrap_or(true) {
        check_symbols(&orig_dynsym, &decomp_dynsym)?;
    }

    eprintln!("{}", "OK".green().bold());
    Ok(())
}

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut args = Args {
        version: repo::get_config().default_version.clone(),
        ..Default::default()
    };

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => {
                args.version = Some(parser.value()?.into_string()?);
            }
            Long("always-diff") => {
                args.always_diff = true;
            }
            Long("warnings-as-errors") => {
                args.warnings_as_errors = true;
            }

            Long("check-mismatch-comments") => {
                args.check_mismatch_comments = true;
            }

            Long("help") | Short('h') => {
                args.print_help = true;
            }

            Value(other_val) if args.function.is_none() => {
                args.function = Some(other_val.into_string()?);
            }
            Value(other_val) if args.function.is_some() => {
                args.other_args.push(other_val.into_string()?);
            }
            Long(other_long) => {
                args.other_args.push(format!("--{other_long}"));
                let opt = parser.optional_value();
                if let Some(o) = opt {
                    args.other_args.push(o.into_string()?);
                }
            }
            Short(other_short) => {
                args.other_args.push(format!("-{other_short}"));
            }

            _ => return Err(arg.unexpected()),
        }
    }

    Ok(args)
}

fn print_help() -> Result<()> {
    println!(
"Usage: check [function name] [--version VERSION] [--always-diff] [--warnings-as-errors] [--check-mismatch-comments] [asm-differ arguments]

Checks if the compiled bytecode of a function matches the assembly found within the game elf. If not, show the differences between them.
If no function name is provided, all functions within the repository function list will be checked.

optional arguments:

 -h, --help             Show this help message and exit
 --version VERSION      Check the function against version VERSION of the game elf
 --always-diff          Show an assembly diff, even if the function matches
 --warnings-as-errors   Errors instead of printing a warning if a function can't be checked (mainly for CI)
 --check-mismatch-comments   Checks that all mismatching functions have a NON_MATCHING comment with a decomp.me link above them
All further arguments are forwarded onto asm-differ.

asm-differ arguments:"
);

    let differ_path = repo::get_tools_path()?.join("asm-differ").join("diff.py");

    // By default, invoking asm-differ using std::process:Process doesn't seem to allow argparse
    // (the python module asm-differ uses to print its help text) to correctly determine the number of columns in the host terminal.
    // To work around this, we'll detect that for it, and set it manually via the COLUMNS environment variable
    let num_columns = match crossterm::terminal::size() {
        Ok((num_columns, _num_rows)) => num_columns,
        Err(_) => 240,
    };

    let output = std::process::Command::new(&differ_path)
        .current_dir(repo::get_tools_path()?)
        .arg("--help")
        .env("COLUMNS", num_columns.to_string())
        .output()
        .with_context(|| format!("failed to launch asm-differ: {:?}", &differ_path))?;

    let asm_differ_help = String::from_utf8_lossy(&output.stdout);

    let asm_differ_arguments = asm_differ_help
        .split("optional arguments:")
        .collect::<Vec<&str>>()
        .get(1)
        .copied()
        .or_else(|| {
            asm_differ_help
                .split("options:")
                .collect::<Vec<&str>>()
                .get(1)
                .copied()
        })
        .unwrap_or(&asm_differ_help);

    println!("{asm_differ_arguments}");

    Ok(())
}

enum CheckResult {
    // If a function does not match, but is marked as such, return this error to show an appropriate exit message.
    MismatchError,
    // If a function does match, but is marked as mismatching, return this warning to indicate this and fix its status.
    MatchWarn,
    // If a function does not match, but is marked as "not decompiled", return this warning to indicate this and fix its status.
    MismatchWarn,
    // Check result matches the expected value listed in the function table.
    Ok,
}

fn check_function(
    checker: &FunctionChecker,
    cs: &mut capstone::Capstone,
    function: &functions::Info,
    addr2line_ctx: &Option<elf::Addr2LineContext>,
    args: &Args,
) -> Result<CheckResult> {
    let name = function.name.as_str();
    let decomp_fn = elf::get_function_by_name(checker.decomp_elf, checker.decomp_symtab, name);

    match function.status {
        Status::NotDecompiled if decomp_fn.is_err() => return Ok(CheckResult::Ok),
        Status::Library => return Ok(CheckResult::Ok),
        _ => (),
    }

    if let Err(error) = decomp_fn {
        ui::print_warning(&format!(
            "couldn't check {}: {}",
            ui::format_symbol_name(name),
            error.to_string().dimmed(),
        ));
        if args.warnings_as_errors {
            return Err(error);
        }
        return Ok(CheckResult::Ok);
    }

    let decomp_fn = decomp_fn.unwrap();

    let get_orig_fn = || {
        elf::get_function(checker.orig_elf, function.addr, function.size as u64).with_context(
            || {
                format!(
                    "failed to get function {} ({}) from the original executable",
                    name,
                    ui::format_address(function.addr),
                )
            },
        )
    };

    match function.status {
        Status::Matching => {
            let orig_fn = get_orig_fn()?;

            let result = checker
                .check(cs, &orig_fn, &decomp_fn)
                .with_context(|| format!("checking {name}"))?;

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
                ui::print_detail_ex(&mut lock, &mismatch.to_string());
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
                .with_context(|| format!("checking {name}"))?;

            if result.is_none() {
                ui::print_note(&format!(
                    "function {} is marked as {} but matches",
                    ui::format_symbol_name(name),
                    function.status.description(),
                ));
                return Ok(CheckResult::MatchWarn);
            } else {
                if args.check_mismatch_comments {
                    let ctx = addr2line_ctx.as_ref().context(
                        "Addr2line context should not be None when checking mismatch comments",
                    )?;
                    let (file, line) =
                        elf::find_file_and_line_by_symbol(checker.decomp_elf, ctx, &function.name)?;
                    check_mismatch_comment(&file, line, &function.name)?;
                }
                if function.status == Status::NotDecompiled {
                    ui::print_note(&format!(
                        "function {} is marked as {} but mismatches",
                        ui::format_symbol_name(name),
                        function.status.description(),
                    ));
                    return Ok(CheckResult::MismatchWarn);
                }
            }
        }

        Status::Library => unreachable!(),
    };

    Ok(CheckResult::Ok)
}

fn check_single(
    checker: &FunctionChecker,
    functions: &[functions::Info],
    all_functions: &[functions::Info],
    fn_to_check: &str,
    args: &Args,
) -> Result<()> {
    let version = args.get_version();
    let filtered_functions =
        functions::filter_candidates_by_symtab(functions, checker.decomp_symtab);
    let function = ui::fuzzy_search_function_interactively(&filtered_functions, fn_to_check)?;
    let name = function.name.as_str();

    eprintln!("{}", ui::format_symbol_name(name).bold());

    if matches!(function.status, Status::Library) {
        bail!("L functions should not be decompiled");
    }

    let resolved_name;
    let name = if checker.decomp_symtab.contains_key(name) {
        name
    } else {
        resolved_name = resolve_unknown_fn_interactively(name, checker.decomp_symtab, functions)?;
        &resolved_name
    };

    let decomp_fn = elf::get_function_by_name(checker.decomp_elf, checker.decomp_symtab, name)
        .with_context(|| {
            format!(
                "failed to get decomp function: {}",
                ui::format_symbol_name(name)
            )
        })?;

    let orig_fn = elf::get_function(checker.orig_elf, function.addr, function.size as u64)?;

    let mut maybe_mismatch = checker
        .check(&mut make_cs()?, &orig_fn, &decomp_fn)
        .with_context(|| format!("checking {name}"))?;

    let mut should_show_diff = args.always_diff;

    if let Some(mismatch) = &maybe_mismatch {
        eprintln!("{}\n{}", "mismatch".red().bold(), &mismatch);
        should_show_diff = true;
    } else {
        eprintln!("{}", "OK".green().bold());
    }

    if should_show_diff {
        show_asm_differ(function, name, &args.other_args, version)?;

        maybe_mismatch =
            rediff_function_after_differ(all_functions, &orig_fn, name, &maybe_mismatch, version)
                .context("failed to rediff")?;
    }

    let new_status = match maybe_mismatch {
        None => Status::Matching,
        _ if function.status == Status::NotDecompiled => Status::Wip,
        _ => function.status.clone(),
    };

    // Update the function entry if needed.
    let status_changed = function.status != new_status;
    let name_was_ambiguous = function.name != name;
    if status_changed || name_was_ambiguous {
        if status_changed {
            ui::print_note(&format!(
                "changing status from {:?} to {:?}",
                function.status, new_status
            ));
        }

        update_function_in_function_list(functions, function.addr, version, |entry| {
            entry.status = new_status.clone();
            entry.name = name.to_string();
        })?;
    }

    Ok(())
}

fn check_all(checker: &FunctionChecker, functions: &[functions::Info], args: &Args) -> Result<()> {
    let failed = atomic::AtomicBool::new(false);
    let new_function_statuses: Mutex<HashMap<u64, functions::Status>> = Mutex::new(HashMap::new());

    functions.par_iter().for_each_init(
        || -> Option<elf::Addr2LineContext> {
            if !args.check_mismatch_comments {
                return None;
            }
            // addr2line structs can't be safely shared between threads, so we create one context
            // per thread (NOT per iteration)
            let ctx = elf::create_addr2line_ctx_for(checker.decomp_elf).expect(
                "The decomp elf should be valid, so creating an addr2line context should work",
            );
            Some(ctx)
        },
        |addr2line_ctx, function| {
            let result = CAPSTONE.with(|cs| -> Result<()> {
                let mut cs = cs.borrow_mut();
                let ok = check_function(checker, &mut cs, function, addr2line_ctx, args)?;
                match ok {
                    CheckResult::MismatchError => {
                        failed.store(true, atomic::Ordering::Relaxed);
                    }
                    CheckResult::MatchWarn => {
                        new_function_statuses
                            .lock()
                            .unwrap()
                            .insert(function.addr, functions::Status::Matching);
                    }
                    CheckResult::MismatchWarn => {
                        new_function_statuses
                            .lock()
                            .unwrap()
                            .insert(function.addr, functions::Status::NonMatchingMajor);
                    }
                    CheckResult::Ok => {}
                }
                Ok(())
            });

            if let Err(e) = result {
                failed.store(true, atomic::Ordering::Relaxed);
                println!("Error while checking function {}: {e}", &function.name);
            }
        },
    );

    update_function_statuses(
        functions,
        &new_function_statuses.lock().unwrap(),
        args.version.as_deref(),
    )
    .with_context(|| "failed to update function statuses")?;

    if failed.load(atomic::Ordering::Relaxed) {
        bail!("found at least one error");
    } else {
        Ok(())
    }
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

fn update_function_statuses(
    functions: &[functions::Info],
    new_function_statuses: &HashMap<u64, functions::Status>,
    version: Option<&str>,
) -> Result<()> {
    if new_function_statuses.is_empty() {
        return Ok(());
    }

    let mut new_functions = functions.to_vec();

    new_functions.par_iter_mut().for_each(|info| {
        if let Some(status) = new_function_statuses.get(&info.addr) {
            info.status = status.clone()
        }
    });

    functions::write_functions(&new_functions, version)
}

fn update_function_in_function_list<UpdateFn>(
    functions: &[functions::Info],
    addr: u64,
    version: Option<&str>,
    update_fn: UpdateFn,
) -> Result<()>
where
    UpdateFn: FnOnce(&mut functions::Info),
{
    let mut new_functions = functions.to_vec();
    let entry = new_functions
        .iter_mut()
        .find(|info| info.addr == addr)
        .unwrap();
    update_fn(entry);
    functions::write_functions(&new_functions, version)
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
    candidates.sort_by_key(|(&name, &sym)| (name, sym.st_value));
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
        let prompt = format!("{ambiguous_name} is ambiguous; did you mean:");
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

fn show_asm_differ(
    function: &functions::Info,
    name: &str,
    differ_args: &[String],
    version: Option<&str>,
) -> Result<()> {
    let differ_path = repo::get_tools_path()?.join("asm-differ").join("diff.py");
    let mut cmd = std::process::Command::new(&differ_path);

    cmd.current_dir(repo::get_tools_path()?)
        .arg("-I")
        .arg("-e")
        .arg(name)
        .arg(format!("0x{:016x}", function.addr))
        .arg(format!("0x{:016x}", function.addr + function.size as u64))
        .args(differ_args);

    if let Some(version) = version {
        cmd.args(["--version", version]);
    }

    cmd.status()
        .with_context(|| format!("failed to launch asm-differ: {:?}", &differ_path))?;

    Ok(())
}

fn rediff_function_after_differ(
    functions: &[functions::Info],
    orig_fn: &elf::Function,
    name: &str,
    previous_check_result: &Option<Mismatch>,
    version: Option<&str>,
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
        .with_context(|| format!("re-checking {name}"))?;

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

fn check_mismatch_comment(
    file_path: &str,
    line: u32,
    function_symbol: &str,
) -> std::io::Result<()> {
    fn rfind_function_metadata_block<'a>(function_symbol: &str, content: &'a str) -> &'a str {
        let function_name = if let Ok(demangled_name) = functions::demangle_str(function_symbol) {
            // Extract the function name from the damngled name (removing the function params and
            // any extra namespaces)
            let function_name_and_namespace = demangled_name
                .split_once("(")
                .expect("Demangled function names should always have an opening parenthesis")
                .0;
            function_name_and_namespace
                .rsplit_once("::")
                .map(|v| v.1)
                .unwrap_or(function_name_and_namespace)
                .to_string()
        } else {
            function_symbol.to_string()
        };

        // Get all content up from the end of the line with the function signature until an empty line
        let fn_signature_start_index = content
            .rfind(&format!("{function_name}("))
            .unwrap_or(content.len() - 1);

        let fn_signature_line_end_index =
            content[fn_signature_start_index..].find("\n").unwrap_or(0) + fn_signature_start_index;
        let content_from_fn_signature_line_end = &content[..fn_signature_line_end_index];
        let start_index = content_from_fn_signature_line_end
            .rfind("\n\n")
            .unwrap_or(0);
        &content_from_fn_signature_line_end[start_index..]
    }

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let lines = reader
        .lines()
        .take(line as usize)
        .collect::<Result<Vec<_>, _>>()?;
    let content = lines.join("\n");

    let function_signature_and_comments = rfind_function_metadata_block(function_symbol, &content);
    let cwd = env::current_dir()?;
    let cwd_str = cwd
        .to_str()
        .expect("The current work dir should always be valid as a str");
    let file_rel_path = file_path
        .strip_prefix(&format!("{cwd_str}/"))
        .unwrap_or(file_path);
    if !function_signature_and_comments.contains("NON_MATCHING") {
        ui::print_warning(&format!("Function at line {} of {} mismatches and should have a `NON_MATCHING` comment above it with a `decomp.me` link", line, file_rel_path));
    } else if !function_signature_and_comments.contains("decomp.me") {
        // Not the full https://decomp.me/scratch to allow for comments like "Same mismatch as above, no decomp.me needed"
        ui::print_warning(&format!(
            "NON_MATCHING comment for function at line {} of {} should have a `decomp.me` link",
            line, file_rel_path
        ));
    }

    Ok(())
}

#[derive(Debug)]
pub enum SymbolMismatchCause {
    // st_size
    Size(u64, u64),
    // st_info
    Bind(u8, u8),
    Type(u8, u8),
    // st_other
    Visibility(u8, u8),
}

impl std::fmt::Display for SymbolMismatchCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match &self {
            Self::Size(_, _) => "Size",
            Self::Bind(_, _) => "Bind",
            Self::Type(_, _) => "Type",
            Self::Visibility(_, _) => "Visibility",
        };
        let orig = match &self {
            Self::Size(orig_size, _) => orig_size.to_string(),
            Self::Bind(orig_bind, _) => goblin::elf::sym::bind_to_str(*orig_bind).to_string(),
            Self::Type(orig_type, _) => goblin::elf::sym::type_to_str(*orig_type).to_string(),
            Self::Visibility(orig_vis, _) => goblin::elf::sym::visibility_to_str(*orig_vis).to_string(),
        };
        let decomp = match &self {
            Self::Size(_, decomp_size) => decomp_size.to_string(),
            Self::Bind(_, decomp_bind) => goblin::elf::sym::bind_to_str(*decomp_bind).to_string(),
            Self::Type(_, decomp_type) => goblin::elf::sym::type_to_str(*decomp_type).to_string(),
            Self::Visibility(_, decomp_vis) => goblin::elf::sym::visibility_to_str(*decomp_vis).to_string(),
        };
        write!(
            f,
            "incorrect {name}; expected to see {orig}\n\
            --> decomp contains {decomp} instead",
            name = name,
            orig = orig,
            decomp = decomp,
        )
    }
}

fn check_symbols(
    orig_dynsym: &elf::SymbolTableByName,
    decomp_dynsym: &elf::SymbolTableByName,
) -> Result<()> {

    let mut mismatching = false;

    for (name, symbol) in orig_dynsym.iter() {
        let Some(decomp_symbol) = decomp_dynsym.get(name) else {
            continue;
        };

        if let Some(mismatch) = check_symbol(symbol, decomp_symbol)? {
            mismatching = true;
            ui::print_error(&format!(
                "symbol {} is different between the original and decomp ELF:\n{}",
                ui::format_symbol_name(name),
                mismatch
            ));
        }
    }

    if mismatching {
        bail!("found at least one error");
    } else {
        Ok(())
    }
}

pub fn check_symbol(symbol: &goblin::elf::Sym, decomp_symbol: &goblin::elf::Sym) -> Result<Option<SymbolMismatchCause>> {
    // mismatching function size will cause issues in FunctionChecker already, so ignore here
    if symbol.st_size != decomp_symbol.st_size && !symbol.is_function() {
        return Ok(Some(SymbolMismatchCause::Size(symbol.st_size, decomp_symbol.st_size)))
    }

    // st_info
    if symbol.st_bind() != decomp_symbol.st_bind() {
        return Ok(Some(SymbolMismatchCause::Bind(symbol.st_bind(), decomp_symbol.st_bind())))
    }
    if symbol.st_type() != decomp_symbol.st_type() {
        return Ok(Some(SymbolMismatchCause::Type(symbol.st_type(), decomp_symbol.st_type())))
    }

    // st_other
    if symbol.st_visibility() != decomp_symbol.st_visibility() {
        return Ok(Some(SymbolMismatchCause::Visibility(symbol.st_visibility(), decomp_symbol.st_visibility())))
    }

    Ok(None)
}
