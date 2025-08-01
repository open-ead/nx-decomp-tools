use anyhow::bail;
use anyhow::Result;
use colored::*;
use itertools::Itertools;
use std::io::StderrLock;
use std::io::Write;
use textwrap::indent;

use crate::elf;
use crate::functions;

pub fn print_note(msg: &str) {
    eprintln!("{}{}{}", "note".bold().cyan(), ": ".bold(), msg.bold())
}

pub fn print_warning(msg: &str) {
    eprintln!("{}{}{}", "warning".bold().yellow(), ": ".bold(), msg.bold())
}

pub fn print_error(msg: &str) {
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    print_error_ex(&mut lock, msg);
}

pub fn print_error_ex(lock: &mut StderrLock, msg: &str) {
    writeln!(
        lock,
        "{}{}{}",
        "error".bold().red(),
        ": ".bold(),
        msg.bold()
    )
    .unwrap();
}

pub fn format_symbol_name(name: &str) -> String {
    functions::demangle_str(name).map_or(name.blue().to_string(), |demangled| {
        format!("{} ({})", demangled.blue(), name.blue().dimmed(),)
    })
}

pub fn format_address(addr: u64) -> String {
    format!("{addr:#x}").green().to_string()
}

pub fn print_detail(msg: &str) {
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    print_detail_ex(&mut lock, msg);
}

pub fn print_detail_ex(lock: &mut StderrLock, msg: &str) {
    writeln!(lock, "{}\n", indent(&msg.clear(), &"  │  ".bold().dimmed())).unwrap();
}

pub fn init_prompt_settings() {
    let mut config = inquire::ui::RenderConfig::default();
    config.prompt.att |= inquire::ui::Attributes::BOLD;
    inquire::set_global_render_config(config);
}

pub fn clear_terminal() {
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::cursor::MoveTo(0, 0),
    )
    .unwrap_or(());
}

pub fn fuzzy_search_function_interactively<'a>(
    functions: &'a [functions::Info],
    decomp_symtab: &elf::SymbolTableByName,
    name: &str,
) -> Result<&'a functions::Info> {
    let existing_functions: Box<_> = functions
        .iter()
        .filter(|function| decomp_symtab.contains_key(function.name.as_str()))
        .collect();
    let candidates = functions::fuzzy_search(&existing_functions, name);
    match candidates[..] {
        [] => bail!("no match for {}", format_symbol_name(name)),
        [exact_match] => Ok(exact_match),
        _ => {
            let prompt = format!(
                "{} is ambiguous (found {} matches); did you mean:",
                name.dimmed(),
                candidates.len()
            );

            clear_terminal();

            let options = candidates
                .iter()
                .map(|info| format_symbol_name(&info.name))
                .collect_vec();

            let selection = inquire::Select::new(&prompt, options)
                .with_starting_cursor(0)
                .with_page_size(crossterm::terminal::size()?.1 as usize / 2)
                .raw_prompt()?
                .index;

            Ok(candidates[selection])
        }
    }
}
