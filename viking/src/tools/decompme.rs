use std::path::PathBuf;

use addr2line::fallible_iterator::FallibleIterator;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use clang::{Clang, Index};
use colored::Colorize;
use std::io::Write;
use tempfile::Builder;
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

#[derive(Debug, Default, Clone, serde::Deserialize)]
struct CreateScratchResponse {
    pub slug: String,
    pub claim_token: String,
}

#[derive(Debug, Default, Clone)]
struct FinalScratchUrl {
    pub base_url: String,
    pub claim_url: String,
}

fn load_compilation_database(args: &Args) -> Result<json_compilation_db::Entries> {
    let mut path;
    if let Some(p) = args.compilation_database.as_ref() {
        path = PathBuf::from(p.to_string());
    } else {
        path = repo::get_build_path(args.version.as_deref())?;
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

struct FunctionTextInfo {
    range_start: usize,
    range_end: usize,
    namespace: String,
}

fn try_find_function_from_ast_entity<'tu>(
    entity: clang::Entity<'tu>,
    fn_name: &str,
) -> Option<FunctionTextInfo> {
    fn get_namespace_string<'tu>(entity: clang::Entity<'tu>) -> String {
        let mut parent = Some(entity);
        let mut namespace = String::new();
        while let Some(p) = parent {
            if p.get_kind() != Namespace {
                break;
            }
            if let Some(name) = p.get_display_name() {
                if !namespace.is_empty() {
                    namespace.insert_str(0, "::");
                }
                namespace.insert_str(0, &name);
            }
            parent = p.get_lexical_parent();
        }
        namespace
    }

    use clang::EntityKind::*;
    for child in entity.get_children() {
        // The enum entry name FunctionDecl is misleading here and it applies to both function
        // declarations and definitions like Method
        if !matches!(child.get_kind(), Method | FunctionDecl | Constructor) {
            let recursion_result = try_find_function_from_ast_entity(child, fn_name);
            if recursion_result.is_some() {
                return recursion_result;
            }
            continue;
        }
        let name = child.get_mangled_name();
        let range = child.get_range();
        if !child.is_definition()
            || range.is_none()
            || name.is_none_or(|name| {
                // On some platfroms libclang mangled symbols have two underscores at the start instead
                // of one
                name.strip_prefix("_").unwrap_or(&name) != fn_name && name != fn_name
            })
        {
            continue;
        }
        let range = range.unwrap();
        let start = range.get_start().get_file_location().offset as usize;
        let end = range.get_end().get_file_location().offset as usize;
        let namespace = get_namespace_string(entity);
        return Some(FunctionTextInfo {
            range_start: start,
            range_end: end,
            namespace,
        });
    }
    None
}

impl TranslationUnit {
    fn get_function_with_libclang(&self, function_name: &str) -> Result<FunctionTextInfo> {
        // Create temporary file to pass as input to libclang. Must have the ".cpp" extension to be
        // parsed correctly
        let mut temp_preprocessed_file = Builder::new().suffix(".cpp").tempfile()?;
        write!(temp_preprocessed_file, "{}", &self.contents)?;
        let clang = Clang::new().map_err(anyhow::Error::msg)?;
        let index = Index::new(&clang, false, false);
        let tu = index.parser(temp_preprocessed_file.path()).parse()?;
        try_find_function_from_ast_entity(tu.get_entity(), function_name)
            .context("Unable to find function from AST")
    }
    pub fn try_get_and_remove_function(&mut self, function_name: &str) -> Result<String> {
        let FunctionTextInfo {
            mut range_start,
            range_end,
            namespace,
        } = self.get_function_with_libclang(function_name)?;
        // Expand function text range to nearest newline before the function to include comments and/or
        // a template assosiated with the function
        if let Some(index) = self.contents[..range_start].rfind("\n\n") {
            range_start = index + 2;
        }
        let mut function_text = self.contents[range_start..range_end].to_string();
        if !namespace.is_empty() {
            function_text = format!("namespace {namespace} {{\n{function_text}\n}}");
        }
        self.contents.replace_range(range_start..range_end, "");
        Ok(function_text)
    }
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

fn get_include_paths(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .skip_while(|&line| line != "#include <...> search starts here:")
        .take_while(|&line| line != "End of search list.")
        .map(|line| line.split_whitespace().next().unwrap())
        .filter(|&path| std::path::Path::new(path).is_dir())
        .collect()
}

fn uninclude_system_includes(stdout: &str, include_paths: &Vec<&str>) -> String {
    let mut result = String::with_capacity(stdout.len());

    // The current include stack.
    struct Include<'a> {
        file: &'a str,
        is_system_header: bool,
    }
    let mut include_stack: Vec<Include> = Vec::new();

    let is_including_system_header = |include_stack: &Vec<Include>| {
        if let Some(include) = include_stack.last() {
            include.is_system_header
        } else {
            false
        }
    };

    for line in stdout.lines() {
        if line.starts_with("# ") {
            let split: Vec<_> = line.split(' ').collect();
            if split.len() >= 4 {
                // [#, lineno, "/path/to/source.cpp", 1, 3]
                let file = split[2].trim_matches('"');
                let flags = &split[3..];
                let is_system_header = flags.contains(&"3");

                let was_including_system_header = is_including_system_header(&include_stack);

                if flags.contains(&"1") {
                    // Start of a new file.
                    include_stack.push(Include {
                        file,
                        is_system_header,
                    });

                    if is_system_header && !was_including_system_header {
                        for path in include_paths {
                            if let Some(relative_include) = file.strip_prefix(path) {
                                result
                                    .push_str(&format!("#include <{}>\n", &relative_include[1..]));
                                break;
                            }
                        }
                    }
                } else if flags.contains(&"2") {
                    // End of an included file.
                    let popped = include_stack.pop();
                    assert!(popped.is_some(), "cannot pop empty include stack");

                    if let Some(current_include) = include_stack.last() {
                        assert_eq!(current_include.file, file);
                    }

                    // Skip the '# ... 2' line as the corresponding '# ... 1' was not emitted.
                    if was_including_system_header {
                        continue;
                    }
                }
            }
        }

        // Skip lines that come from a system header, as those have been replaced with an #include.
        if is_including_system_header(&include_stack) {
            continue;
        }

        result.push_str(line);
        result.push('\n');
    }

    result
}

fn run_preprocessor(entry: &json_compilation_db::Entry) -> Result<String> {
    let mut command = entry.arguments.clone();
    remove_c_and_output_flags(&mut command);

    let output = std::process::Command::new(&command[0])
        .current_dir(&entry.directory)
        .args(&command[1..])
        .arg("-E")
        .arg("-C")
        .arg("-v")
        .output()?;

    // Yes, we're assuming the source code uses UTF-8.
    // No, we don't care about other encodings like SJIS.
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;

    // Post-process the preprocessed output to make it smaller by un-including
    // system headers (e.g. C and C++ standard library headers).
    let include_paths = get_include_paths(stderr);
    let result = uninclude_system_includes(stdout, &include_paths);

    Ok(result)
}

fn get_translation_unit(
    source_file: &str,
    compilation_db: &json_compilation_db::Entries,
) -> Result<TranslationUnit> {
    let canonical_path = PathBuf::from(source_file).canonicalize()?;

    let entry = compilation_db
        .iter()
        .find(|entry| entry.file == canonical_path)
        .with_context(|| format!("failed to find source file {source_file}"))?;

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
    demangled_name: &str,
    args: &Args,
    decomp_me_config: &repo::ConfigDecompMe,
    info: &functions::Info,
    flags: Option<&str>,
    context: &str,
    source_code: &str,
    disassembly: &str,
) -> Result<FinalScratchUrl> {
    let client = reqwest::blocking::Client::new();

    #[derive(serde::Serialize)]
    struct Data {
        platform: String,
        name: String,
        target_asm: String,
        source_code: String,
        context: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        diff_label: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        compiler: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        compiler_flags: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        preset: Option<String>,
    }

    let show_name = demangled_name.to_owned()

    let data = Data {
        platform: "switch".to_string(),
        name: show_name,
        target_asm: disassembly.to_string(),
        source_code: source_code.to_string(),
        context: context.to_string(),
        diff_label: Some(info.name.clone()),
        compiler: decomp_me_config.compiler_name.clone(),
        compiler_flags: flags.map(|s| s.to_string()),
        preset: decomp_me_config.preset_id.clone(),
    };

    let res_text = client
        .post(format!("{}/api/scratch", &args.decomp_me_api))
        .json(&data)
        .send()?
        .text()?;

    let res = serde_json::from_str::<CreateScratchResponse>(&res_text);

    if let Some(error) = res.as_ref().err() {
        ui::print_error(&format!("failed to upload function: {error}"));
        ui::print_note(&format!(
            "server response:\n{}\n",
            &res_text.normal().yellow()
        ));
        bail!("failed to upload function");
    }

    let res_data = res.unwrap();

    let base_url = format!("{}/scratch/{}/", args.decomp_me_api, res_data.slug);
    let claim_url = format!("{}/scratch/{}/claim?token={}", args.decomp_me_api, res_data.slug, res_data.claim_token);

    Ok(FinalScratchUrl {
        base_url: base_url,
        claim_url: claim_url,
    })
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
                    write!(f, " {}", x.wrapping_sub(insn.address()))?
                }
                _ => write!(f, " {op}")?,
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

/// Returns a path to the source file where the specified function is defined.
fn deduce_source_file_from_debug_info(
    decomp_elf: &elf::OwnedElf,
    function_name: &str,
) -> Result<String> {
    let symbol = elf::find_function_symbol_by_name(decomp_elf, function_name)?;

    let data: &[u8] = &decomp_elf.as_owner().1;
    let file = addr2line::object::read::File::parse(data)?;
    let ctx = addr2line::Context::new(&file)?;

    // Grab the location of the last frame (we choose the last frame to ignore inline function frames).
    let frame = ctx
        .find_frames(symbol.st_value)?
        .last()?
        .context("no frame found")?;

    let loc = frame.location.context("no location found")?;
    let file = loc.file.context("no file found")?;

    Ok(file.to_string())
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let config = repo::get_config();
    let decomp_me_config = config
        .decomp_me
        .as_ref()
        .context("decomp.me integration needs to be configured")?;

    let functions = functions::get_functions(args.version.as_deref())?;

    let function_info = ui::fuzzy_search_function_interactively(&functions, &args.function_name)?;

    let demangled_name = functions::demangle_str(&function_info.name)?;

    eprintln!("{}", ui::format_symbol_name(&function_info.name).bold());

    let version = args.version.as_deref();
    let decomp_elf = elf::load_decomp_elf(version)?;
    let orig_elf = elf::load_orig_elf(version)?;
    let function = elf::get_function(&orig_elf, function_info.addr, function_info.size as u64)?;
    let disassembly = get_disassembly(function_info, &function)?;

    let mut flags = decomp_me_config.default_compile_flags.clone();
    let mut context = "".to_string();

    // Fill in compile flags and the context using the compilation database
    // and the specified source file.
    let source_file = args
        .source_file
        .clone()
        .or_else(|| deduce_source_file_from_debug_info(&decomp_elf, &function_info.name).ok());

    let mut source_code = String::new();
    if let Some(source_file) = source_file.as_deref() {
        println!("source file: {}", &source_file.dimmed());

        let compilation_db =
            load_compilation_database(&args).context("failed to load compilation database")?;

        let mut tu = get_translation_unit(source_file, &compilation_db)
            .context("failed to get translation unit")?;

        let function_text = tu
            .try_get_and_remove_function(&function_info.name)
            .unwrap_or_else(|err| {
                ui::print_note(&format!("Unable to automatically move function to source code tab (caused by error: {})", &err));
                "// move the target function from the context to the source tab".to_string()
            });

        source_code = format!(
            "// function name: {}\n\
         // original address: {:#x} \n\
         \n\
         {}",
            &function_info.name,
            function_info.get_start(),
            &function_text
        );

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

        if decomp_me_config.override_compile_flags.unwrap_or(true) && flags.is_some() {
            flags = Some(format!("{} -x c++", command.join(" ")));

        }
    } else {
        ui::print_warning(
            "consider passing -s [.cpp source] so that the context can be automatically filled",
        );
    }

    if decomp_me_config.compiler_name.is_none() && decomp_me_config.preset_id.is_none() {
        ui::print_error("please specify either: \n- preset_id (You can get it from https://decomp.me/preset or suggest a new one via github issues) \nor \n- compiler_name and\n- default_compile_flags");
        ui::print_error(
            "please specify either: \n\
            - preset_id (You can get it from https://decomp.me/preset or suggest a new one via github issues)\n\
            or\n\
            - compiler_name and\n\
            - default_compile_flags"
        );
        bail!("missing required configuration");
    }

    println!("context: {} lines", context.matches('\n').count());
    if let Some(flags_str) = flags.as_ref() {
        println!("compile flags: {flags_str}");
    }
    if let Some(preset_id) = decomp_me_config.preset_id.as_ref() {
        println!("preset id: {preset_id}");
    }

    let confirm = inquire::Confirm::new("Upload?")
        .with_default(true)
        .with_help_message("note that your source file paths will be revealed if you continue");
    if !confirm.prompt()? {
        bail!("cancelled");
    }

    println!("uploading...");

    let urls = create_scratch(
        &demangled_name,
        &args,
        decomp_me_config,
        function_info,
        flags.as_deref(),
        &context,
        &source_code,
        &disassembly,
    )
    .context("failed to create scratch")?;

    ui::print_note(&format!(
        "created scratch for \'{}\'.\n\n\
        Claim: {}\n\
        Direct: {}",
        demangled_name,
        urls.claim_url,
        urls.base_url
    ));

    Ok(())
}
