use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use colored::Colorize;
use viking::elf;
use viking::functions;
use viking::repo;
use viking::ui;

#[derive(FromArgs)]
/// Upload a function to decomp.me.
struct Args {
    /// version
    #[argh(option)]
    version: Option<String>,

    /// decomp.me API endpoint base
    #[argh(option, default = r#""https://decomp.me".to_string()"#)]
    decomp_me_api: String,

    /// path to compilation database
    #[argh(option, short = 'p')]
    compilation_database: Option<String>,

    /// source file to preprocess and upload
    #[argh(option, short = 's')]
    source_file: Option<String>,

    /// name of the function to upload
    #[argh(positional)]
    function_name: String,
}

fn load_compilation_database(args: &Args) -> Result<json_compilation_db::Entries> {
    let mut path;
    if let Some(p) = args.compilation_database.as_ref() {
        path = PathBuf::from(p.to_string());
    } else {
        path = repo::get_build_path(&args.version.as_deref())?;
    }

    if path.is_dir() {
        path.push("compile_commands.json");
    }

    // Read the whole file at once and parse the JSON manually.
    // json_compilation_db::from_file is terribly slow.
    let data = std::fs::read(&path).context("failed to read compilation database")?;

    serde_json::from_slice(&data).context("failed to parse compilation database")
}

struct TranslationUnit {
    command: Vec<String>,
    contents: String,
    path: String,
}

fn remove_c_and_output_flags(command: &mut Vec<String>) {
    let mut remove_next = false;
    command.retain(|arg| {
        if remove_next {
            remove_next = false;
            return false;
        }
        if arg == "-c" {
            return false;
        }
        if arg == "-o" {
            remove_next = true;
            return false;
        }
        true
    });
}

fn run_preprocessor(entry: &json_compilation_db::Entry) -> Result<String> {
    let mut command = entry.arguments.clone();
    remove_c_and_output_flags(&mut command);

    let output = std::process::Command::new(&command[0])
        .current_dir(&entry.directory)
        .args(&command[1..])
        .arg("-E")
        .output()?;

    // Yes, we're assuming the source code uses UTF-8.
    // No, we don't care about other encodings like SJIS.
    Ok(std::str::from_utf8(&output.stdout)?.to_string())
}

fn get_translation_unit(
    args: &Args,
    compilation_db: &json_compilation_db::Entries,
) -> Result<TranslationUnit> {
    if args.source_file.is_none() {
        bail!("no source file specified")
    }

    let canonical_path = PathBuf::from(args.source_file.as_ref().unwrap()).canonicalize()?;

    let entry = compilation_db
        .iter()
        .find(|entry| entry.file == canonical_path)
        .context("failed to find source file")?;

    let command = entry.arguments.clone();
    let contents = run_preprocessor(entry).context("failed to run preprocessor")?;

    Ok(TranslationUnit {
        command,
        contents,
        path: entry.file.to_string_lossy().to_string(),
    })
}

/// Returns the URL of the scratch if successful.
fn create_scratch(
    args: &Args,
    decomp_me_config: &repo::ConfigDecompMe,
    info: &functions::Info,
    flags: &str,
    context: &str,
    source_code: &str,
    disassembly: &str,
) -> Result<String> {
    let client = reqwest::blocking::Client::new();

    #[derive(serde::Serialize)]
    struct Data {
        compiler: String,
        compiler_flags: String,
        platform: String,
        name: String,
        diff_label: Option<String>,
        target_asm: String,
        source_code: String,
        context: String,
    }

    let data = Data {
        compiler: decomp_me_config.compiler_name.clone(),
        compiler_flags: flags.to_string(),
        platform: "switch".to_string(),
        name: info.name.clone(),
        diff_label: Some(info.name.clone()),
        target_asm: disassembly.to_string(),
        source_code: source_code.to_string(),
        context: context.to_string(),
    };

    let res_text = client
        .post(format!("{}/api/scratch", &args.decomp_me_api))
        .json(&data)
        .send()?
        .text()?;

    #[derive(serde::Deserialize)]
    struct ResponseData {
        slug: String,
    }

    let res = serde_json::from_str::<ResponseData>(&res_text);

    if let Some(error) = res.as_ref().err() {
        ui::print_error(&format!("failed to upload function: {}", error));
        ui::print_note(&format!(
            "server response:\n{}\n",
            &res_text.normal().yellow()
        ));
        bail!("failed to upload function");
    }

    let res_data = res.unwrap();

    Ok(format!("{}/scratch/{}", args.decomp_me_api, res_data.slug))
}

// Reimplement fmt::Display to use relative offsets rather than absolute addresses for labels.
struct InstructionWrapper(bad64::Instruction);
impl std::fmt::Display for InstructionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let insn = &self.0;

        write!(f, "{}", insn.op())?;

        for (index, op) in insn.operands().iter().enumerate() {
            if index != 0 {
                write!(f, ",")?;
            }

            match op {
                bad64::Operand::Label(bad64::Imm::Unsigned(x)) => {
                    write!(f, " {}", x - insn.address())?
                }
                _ => write!(f, " {}", op)?,
            }
        }

        Ok(())
    }
}

fn get_disassembly(function_info: &functions::Info, function: &elf::Function) -> Result<String> {
    let mut disassembly = String::new();

    disassembly += &function_info.name;
    disassembly += ":\n";

    let iter = bad64::disasm(function.code, function.addr);

    for maybe_insn in iter {
        if maybe_insn.is_err() {
            bail!("failed to disassemble: {:?}", maybe_insn)
        }

        let insn = InstructionWrapper(maybe_insn.unwrap());
        disassembly += &insn.to_string();
        disassembly.push('\n');
    }

    Ok(disassembly)
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let config = repo::get_config();
    let decomp_me_config = config
        .decomp_me
        .as_ref()
        .context("decomp.me integration needs to be configured")?;

    let functions = functions::get_functions(&args.version.as_deref())?;

    let function_info = functions::find_function_fuzzy(&functions, &args.function_name)
        .context("unknown function")?;

    eprintln!("{}", ui::format_symbol_name(&function_info.name).bold());

    let orig_elf = elf::load_orig_elf(&args.version.as_deref())?;
    let function = elf::get_function(&orig_elf, function_info.addr, function_info.size as u64)?;
    let disassembly = get_disassembly(function_info, &function)?;

    let mut flags = decomp_me_config.default_compile_flags.clone();
    let mut context = "".to_string();
    let source_code = "// move the target function from the context to the source tab";

    // Fill in compile flags and the context using the compilation database
    // and the specified source file.
    if args.source_file.is_some() {
        let compilation_db =
            load_compilation_database(&args).context("failed to load compilation database")?;

        let tu = get_translation_unit(&args, &compilation_db)
            .context("failed to get translation unit")?;

        context = tu.contents.clone();

        let mut command = tu.command.clone();
        remove_c_and_output_flags(&mut command);
        // Remove the compiler command name.
        command.remove(0);
        // Remove the sysroot parameter, include dirs and source file path.
        command.retain(|arg| {
            if arg.starts_with("--sysroot=") {
                return false;
            }
            if arg.starts_with("-I") {
                return false;
            }
            if arg == &tu.path {
                return false;
            }
            true
        });

        flags = command.join(" ");
        flags += " -x c++";
    } else {
        ui::print_warning(
            "consider passing -s [.cpp source] so that the context can be automatically filled",
        );
    }

    println!("context: {} lines", context.matches('\n').count());
    println!("compile flags: {}", &flags.dimmed());

    let confirm = inquire::Confirm::new("Upload?")
        .with_default(true)
        .with_help_message("note that your source file paths will be revealed if you continue");
    if !confirm.prompt()? {
        bail!("cancelled");
    }

    println!("uploading...");

    let url = create_scratch(
        &args,
        decomp_me_config,
        function_info,
        &flags,
        &context,
        source_code,
        &disassembly,
    )
    .context("failed to create scratch")?;

    ui::print_note(&format!("created scratch: {}", &url));

    Ok(())
}
