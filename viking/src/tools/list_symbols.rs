use anyhow::Result;
use argh::FromArgs;
use colored::Colorize;
use goblin::{
    elf::Sym,
    elf64::sym::{STT_FILE, STT_NOTYPE, STT_OBJECT},
};
use itertools::Itertools;
use viking::{elf, functions};

#[derive(FromArgs)]
/// Print symbols in the output ELF.
struct Args {
    /// show symbols that are undefined (e.g. unimplemented functions)
    #[argh(switch, short = 'u')]
    show_undefined: bool,

    /// show data symbols
    #[argh(switch, short = 'd')]
    show_data: bool,

    /// show symbols that are listed as decompiled in the function CSV
    #[argh(switch, short = 'l')]
    show_decompiled: bool,

    /// show only symbols containing the specified substring
    #[argh(positional)]
    filter: Option<String>,

    /// version
    #[argh(option)]
    version: Option<String>,
}

fn main() -> Result<()> {
    colored::control::set_override(true);

    let args: Args = argh::from_env();

    let functions = functions::get_functions(args.version.as_deref())?;
    let known_funcs = functions::make_known_function_name_map(&functions);

    let elf = elf::load_decomp_elf(args.version.as_deref())?;
    let symtab = elf::SymbolStringTable::from_elf(&elf)?;

    let filter = |sym: &Sym| {
        if sym.st_type() == STT_NOTYPE && sym.st_value != 0 {
            return false;
        }

        if sym.st_type() == STT_FILE {
            return false;
        }

        if !args.show_undefined && elf::is_undefined_sym(sym) {
            return false;
        }

        if !args.show_data && sym.st_type() == STT_OBJECT {
            return false;
        }

        true
    };

    let mut prev_addr = 0u64;

    for symbol in elf
        .syms
        .iter()
        .filter(filter)
        .sorted_by_key(|sym| sym.st_value)
    {
        // Skip duplicate symbols (e.g. C1 / C2 for ctors in classes that do not use virtual inheritance).
        // Because the C1 symbol is usually emitted first, this means that C1 will be printed but not C2.
        if symbol.st_value != 0 && symbol.st_value == prev_addr {
            continue;
        }
        prev_addr = symbol.st_value;

        let name = symtab.get_string(symbol.st_name);
        let func_entry = known_funcs.get(name);

        if let Some(func_entry) = func_entry {
            if !args.show_decompiled && func_entry.is_decompiled() {
                continue;
            }
        }

        let demangled_name = functions::demangle_str(name).unwrap_or_else(|_| name.to_string());

        if let Some(filter) = &args.filter {
            if !demangled_name.contains(filter) && !name.contains(filter) {
                continue;
            }
        }

        let status = if elf::is_undefined_sym(&symbol) {
            "undef  ".red().bold()
        } else if symbol.st_type() == STT_OBJECT {
            "data   ".normal().bold()
        } else if let Some(func_entry) = func_entry {
            if func_entry.is_decompiled() {
                "listed ".green().bold()
            } else {
                "listed ".cyan().bold()
            }
        } else {
            "unknown".yellow().bold()
        };

        println!("{} {} ({})", status, &demangled_name, name.dimmed());
    }

    Ok(())
}
