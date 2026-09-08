import json
import os
import tempfile
import subprocess
from pathlib import Path

# -------------
# CONFIGURATION

INCLUDE_OVERRIDE = {
    "math/seadMatrixCalcCommon.hpp": "",
}

def is_header_allowed(path: str) -> bool:
    if not path.endswith(".h"):
        return False
    if "/cafe/" in path.replace("\\", "/"):
        return False
    if "seadScopeGuard.h" in path:
        return False
    return True

# -------------
# CODE

IGNORED_TYPES = [
    "ptrdiff_t",
    "uintptr_t",
    "intptr_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "intmax_t",
    "uint32_t",
    "uintmax_t",
    "int_fast8_t",
    "int_fast64_t",
    "int_least8_t",
    "int_least16_t",
    "int_least32_t",
    "int_least64_t",
    "uint_fast8_t",
    "uint_fast64_t",
    "uint_least8_t",
    "uint_least16_t",
    "uint_least32_t",
    "uint_least64_t",
    "int_fast16_t",
    "int_fast32_t",
    "uint_fast16_t",
    "uint_fast32_t",
    "float_t",
    "double_t",
    "ulong",
    "wchar_t",
    "imaxdiv_t",
    "pid_t",
    "uid_t",
    "__builtin_va_list",
    "va_list",
    "gid_t",
    "__locale_struct",
    "locale_t",
    "wint_t",
    "wctype_t",
    "_IO_FILE",
    "FILE",
    "__mbstate_t",
    "mbstate_t",
    "tm",
    "iovec",
    "ssize_t",
    "off_t",
    "_G_fpos64_t",
    "fpos_t",
    "cookie_read_function_t",
    "cookie_write_function_t",
    "cookie_seek_function_t",
    "cookie_close_function_t",
    "div_t",
    "ldiv_t",
    "lldiv_t",
    "_IO_cookie_io_functions_t",
    "cookie_io_functions_t",
    "msghdr",
    "cmsghdr",
    "ucred",
    "mmsghdr",
    "linger",
    "sockaddr_storage",
    "in_port_t",
    "in_addr_t",
    "in_addr",
    "sockaddr_in",
    "in6_addr",
    "sockaddr_in6",
    "ipv6_mreq",
    "ip_opts",
    "ip_mreq",
    "ip_mreqn",
    "ip_mreq_source",
    "ip_msfilter",
    "group_req",
    "group_source_req",
    "group_filter",
    "in_pktinfo",
    "in6_pktinfo",
    "ip6_mtuinfo",
    "timespec",
    "__sigset_t",
    "sigset_t",
    "suseconds_t",
    "timeval",
    "fd_mask",
    "fd_set",
    "Elf32_Half",
    "Elf64_Half",
    "Elf32_Word",
    "Elf32_Sword",
    "Elf64_Word",
    "Elf64_Sword",
    "Elf32_Xword",
    "Elf32_Sxword",
    "Elf64_Xword",
    "Elf64_Sxword",
    "Elf32_Addr",
    "Elf64_Addr",
    "Elf32_Off",
    "Elf64_Off",
    "Elf32_Section",
    "Elf64_Section",
    "Elf32_Versym",
    "Elf64_Versym",
    "Elf32_Ehdr",
    "Elf64_Ehdr",
    "Elf32_Shdr",
    "Elf64_Shdr",
    "Elf32_Sym",
    "Elf64_Sym",
    "Elf32_Syminfo",
    "Elf64_Syminfo",
    "Elf32_Rel",
    "Elf64_Rel",
    "Elf32_Rela",
    "Elf64_Rela",
    "Elf32_Phdr",
    "Elf64_Phdr",
    "Elf32_Dyn",
    "Elf64_Dyn",
    "Elf32_Verdef",
    "Elf64_Verdef",
    "Elf32_Verdaux",
    "Elf64_Verdaux",
    "Elf32_Verneed",
    "Elf64_Verneed",
    "Elf32_Vernaux",
    "Elf64_Vernaux",
    "Elf32_auxv_t",
    "Elf64_auxv_t",
    "Elf32_Nhdr",
    "Elf64_Nhdr",
    "Elf32_Move",
    "Elf64_Move",
    "Elf32_gptab",
    "Elf32_RegInfo",
    "Elf_Options",
    "Elf_Options_Hw",
    "Elf32_Lib",
    "Elf64_Lib",
    "Elf32_Conflict",
    "wctrans_t",
    "netent",
    "hostent",
    "servent",
    "protoent",
    "nfds_t",
    "pollfd",
    "size_t",
    "uint8_t",
    "uint16_t",
    "uint64_t",
    "u32",
    "u64",
    "socklen_t",
    "sa_family_t",
    "sockaddr",
    "addrinfo",
    "time_t",
]

def adapted_path_wsl(path: str) -> str:
    # if path starts with double backslash, we're calling this from windows using a UNC path (or drive letter, auto-resolved) => convert to WSL path
    if path.startswith("\\\\wsl.localhost"):
        cmd = ["wsl", "--", "wslpath", "-u", path.replace("\\", "/")]
        return subprocess.check_output(cmd).decode().strip()
    # if path starts with single forward slash, we're calling this from Linux => unchanged
    if path.startswith("/"):
        return path
    # unknown path format => raise error
    raise RuntimeError(f"Unknown path to project directory: {path}. Expected either starting with `/` (Linux) or `\\\\wsl$` or `\\\\wsl.localhost` (Windows UNC path).")

PATH = str(Path(__file__).resolve().parent.parent.parent.parent).replace("\\\\wsl$", "\\\\wsl.localhost")
OLD_PATH = adapted_path_wsl(PATH)

# get `-U` options to undo IDA's default declarations
# required for example with `_gs`, as our source code might contain this within variable names
def get_undeclares_ida():
    # excerpt from IDA's default declarations when running the parser
    IDA_DECLARATIONS = """
    -D_cdecl=__cdecl
    -D_pascal=__pascal
    -D_stdcall=__stdcall
    -D_fastcall=__fastcall
    -D_thiscall=__thiscall
    -D_export=__export
    -D_import=__import
    -D__bitmask=__attribute__((flag_enum))
    -D__bin=__attribute__((annotate("__bin")))
    -D__oct=__attribute__((annotate("__oct")))
    -D__hex=__attribute__((annotate("__hex")))
    -D__dec=__attribute__((annotate("__dec")))
    -D__float=__attribute__((annotate("__float")))
    -D__char=__attribute__((annotate("__char")))
    -D__segm=__attribute__((annotate("__segm")))
    -D__off=__attribute__((annotate("__off")))
    -D__invsign=__attribute__((annotate("__invsign")))
    -D__invbits=__attribute__((annotate("__invbits")))
    -D__lzero=__attribute__((annotate("__lzero")))
    -D__sbin=__attribute__((annotate("__sbin")))
    -D__soct=__attribute__((annotate("__soct")))
    -D__shex=__attribute__((annotate("__shex")))
    -D__udec=__attribute__((annotate("__udec")))
    -D__signed=__attribute__((annotate("__signed")))
    -D__enum(...)=__attribute__((annotate("__enum("#__VA_ARGS__")")))
    -D__offset(...)=__attribute__((annotate("__offset("#__VA_ARGS__")")))
    -D__strlit(...)=__attribute__((annotate("__strlit("#__VA_ARGS__")")))
    -D__stroff(...)=__attribute__((annotate("__stroff("#__VA_ARGS__")")))
    -D__custom(...)=__attribute__((annotate("__custom("#__VA_ARGS__")")))
    -D__tabform(...)=__attribute__((annotate("__tabform("#__VA_ARGS__")")))
    -D_Bool=bool
    -D__cppobj=[[clang::annotate("__cppobj")]]
    -D__unaligned=[[clang::annotate("__unaligned")]]
    -D__tuple=struct[[clang::annotate("__tuple")]]
    -D__objc_interface=struct[[clang::annotate("__objc_interface")]]
    -D__fixed(...)=__attribute__((annotate("__fixed("#__VA_ARGS__")")))
    -D__at(...)=__attribute__((annotate("__at("#__VA_ARGS__")")))
    -D__export
    -D__import
    -D__huge=[[clang::annotate_type("__far")]]
    -D__far=[[clang::annotate_type("__far")]]
    -D__near=[[clang::annotate_type("__near")]]
    -D_es=[[clang::annotate_type("_es")]]
    -D_cs=[[clang::annotate_type("_cs")]]
    -D_ss=[[clang::annotate_type("_ss")]]
    -D_ds=[[clang::annotate_type("_ds")]]
    -D__ptr32=[[clang::annotate_type("__ptr32")]]
    -D__ptr64=[[clang::annotate_type("__ptr64")]]
    -D__restrict=[[clang::annotate_type("__restrict")]]
    -D__shifted(...)=[[clang::annotate_type("__shifted("#__VA_ARGS__")")]]
    -D__pure=[[clang::annotate_type("__pure")]]
    -D__unused=[[clang::annotate("__unused")]]
    -D__hidden=[[clang::annotate_type("__hidden")]]
    -D__return_ptr=[[clang::annotate_type("__return_ptr")]]
    -D__struct_ptr=[[clang::annotate_type("__struct_ptr")]]
    -D__array_ptr=[[clang::annotate_type("__array_ptr")]]
    -D__noreturn=__attribute__((noreturn))
    -D__usercall=[[clang::annotate_type("__usercall")]]
    -D__userpurge=[[clang::annotate_type("__userpurge")]]
    -D__spoi(rl)=[[clang::annotate_type("__spoils<" rl ">")]]
    -D_(rl)=[[clang::annotate("@<" rl ">")]]
    -D__gc=
    -D__golang=[[clang::annotate_type("__golang")]]
    -D__gostk=[[clang::annotate_type("__gostk")]]
    """

    # replace `-D` with `-U` to undo declarations
    entries = []
    for line in IDA_DECLARATIONS.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("-D"):
            entry = line[2:].split("=", 1)[0].strip()
            entry = entry.split("(", 1)[0].strip()
            entries.append("-U"+entry)
    return entries

# read `build/compile_commands.json` to get arguments used on SAMPLE_FILE,
# possibly adapt them if switching between WSL and non-WSL
def get_parser_argv():
    with open(PATH+"/build/compile_commands.json") as f:
        compile_commands = json.load(f)

    # find first entry in `/src` dir and use its compiler command
    args = None
    for entry in compile_commands:
        if entry["file"].startswith(OLD_PATH+"/src"):
            args = entry["command"]
            break

    if args is None:
        print("Could not find compile command for sample file.")
        exit(1)

    argv = []
    gobble_next = None
    drop_next = False
    for arg in args.split():
        if drop_next:
            drop_next = False
            continue
        elif gobble_next is not None:
            if gobble_next:
                arg = arg.replace(OLD_PATH, PATH)
            argv[-1] += " " + arg
            gobble_next = None
        elif arg.endswith("/bin/clang"):
            continue
        elif arg.startswith("--target="):
            argv.append(arg)
        elif arg.startswith("--sysroot="):
            argv.append(arg.replace(OLD_PATH, PATH))
        elif arg == "-D":
            argv.append(arg)
            gobble_next = False
        elif arg.startswith("-D"):
            argv.append(arg)
        elif arg.startswith("-I"):
            argv.append(arg.replace(OLD_PATH, PATH))
        elif arg == "-isystem":
            argv.append(arg)
            gobble_next = True
        elif arg.startswith("-std="):
            argv.append(arg)
        elif arg == "-g":
            continue
        elif arg == "-O3":
            continue
        elif arg == "--gcc-toolchain":
            continue
        elif arg.startswith("-f"):
            continue
        elif arg.startswith("-W"):
            continue
        elif arg.startswith("-m"):
            argv.append(arg)
        elif arg.startswith("-stdlib"):
            argv.append(arg)
        elif arg == "-idirafter":
            argv.append(arg)
            gobble_next = True
        elif arg.startswith("--gcc-toolchain"):
            continue
        elif arg.startswith("-o"):
            drop_next = True
        elif arg.startswith("-c"):
            drop_next = True
        else:
            print("Unknown argument:", arg)
    return argv

def create_all_header(file_all):
    with open(file_all, "w") as f:
        def list_all(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    path = os.path.join(root, file)
                    if not is_header_allowed(path):
                        continue
                    f.write("#include \"%s\"\n" % path)

        list_all(PATH+"/src")
        list_all(PATH+"/lib")

tp = tempfile.TemporaryDirectory()
print("Using temporary directory:", tp.name)

file_all = os.path.join(tp.name, "all.h")
create_all_header(file_all)

for header, content in INCLUDE_OVERRIDE.items():
    file = Path(tp.name) / "include_override" / header
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content)

argv = get_parser_argv()
argv = ["-I"+os.path.join(tp.name, "include_override")] + argv + get_undeclares_ida()

ida_srclang.set_parser_argv("clang", " ".join(argv))

til = idaapi.new_til("imported", "newly imported types")
main_til = ida_typeinf.get_idati()

def ida_print_decl(ordinal):
    decl = idc.print_decls(str(ordinal), idaapi.PRTYPE_1LINE)
    if "/* WARNING" in decl:
        print("Type with ordinal %d has warning in decl: %s" % (ordinal, decl))
        exit(1)
    if not decl.split("\n", 1)[0] == f"/* {ordinal} */":
        print("Type with ordinal %d has unexpected decl format: %s" % (ordinal, decl))
        exit(1)
    return decl.split("\n", 1)[1]

class IDAProgressReporter:
    PREFIX = "NODELAY\nHIDECANCEL\n"
    STEPS = 5
    def __init__(self):
        self.message = "Waiting for progress report..."
        self.total_steps = None
        self.step = 0
    
    def iter(self, iterable, message):
        l = list(iterable)
        self.next_step(message, total_steps=len(l))
        class IterableProgressReporter:
            def __init__(self, iterable, reporter):
                self.iterable = iterable
                self.reporter = reporter
            def __iter__(self):
                for i, item in enumerate(self.iterable):
                    self.reporter.report(i)
                    yield item
        return IterableProgressReporter(l, self)
    
    def next_step(self, message, total_steps=None):
        self.message = message
        self.total_steps = total_steps
        self.step += 1
        self.report(0)

    def report(self, step):
        if step % 1234 == 0:
            postfix = f" ({step}/{self.total_steps})" if self.total_steps is not None else ""
            prefix = f"Step {self.step} / {self.STEPS}:\n"
            ida_kernwin.replace_wait_box(self.PREFIX + prefix + self.message + postfix)
    
    def show(self):
        ida_kernwin.show_wait_box(self.PREFIX + self.message)
    def hide(self):
        ida_kernwin.hide_wait_box()

progress = IDAProgressReporter()
try:
    progress.show()

    progress.next_step("Parsing declarations from all headers...")
    errors = ida_srclang.parse_decls_with_parser_ext("clang", til, file_all, idaapi.HTI_FIL)
    print("Done, parsed %d declarations with %d errors." % (len(list(til.named_types())), errors))

    types_backup = {}
    for t in progress.iter(til.named_types(), "Backing up old types..."):
        name = t.get_type_name()
        if name in IGNORED_TYPES:
            continue
        main_t = main_til.get_named_type(name)
        if main_t is None:  # type does not exist yet
            continue
        ordinal = main_t.get_ordinal()
        if ordinal == 0:  # type does not exist yet
            types_backup[name] = "ERROR: could not fetch type from main til"
            print("Could not fetch type with name %s from main til" % name)
            errors += 1
            continue
        if main_t.get_forward_type() == 13:  # forward declaration
            continue
        types_backup[name] = ida_print_decl(ordinal)

    ordinals = {}
    for t in progress.iter(main_til.numbered_types(), "Backing up ordinals..."):
        if ordinals.get(t.get_type_name()) is not None:
            print("Type with name %s has multiple ordinals in main til" % t.get_type_name())
            errors += 1
        ordinals[t.get_type_name()] = t.get_ordinal()

    for t in progress.iter(til.named_types(), "Moving types from temporary til to main til..."):
        if t.get_type_name() in IGNORED_TYPES:
            continue
        main_t = main_til.get_named_type(t.get_type_name())
        if t.get_forward_type() == 13 and main_t is not None and main_t.get_forward_type() != 13:  # forward declaration
            continue

        if t.get_type_name() in ordinals:  # existing type => replace existing ordinal
            t.set_numbered_type(main_til, ordinals.get(t.get_type_name(), 0), ida_typeinf.NTF_COPY|ida_typeinf.NTF_REPLACE, t.get_type_name())
        else:  # new type => do not override existing ordinal
            t.set_named_type(main_til, t.get_type_name(), ida_typeinf.NTF_COPY|ida_typeinf.NTF_REPLACE)

    num_new = 0
    num_unchanged = 0
    num_ignored = 0
    conflicts = {}

    for t in progress.iter(til.named_types(), "Comparing with backup..."):
        name = t.get_type_name()
        if name in IGNORED_TYPES:
            num_ignored += 1
            continue
        ordinal = ida_typeinf.get_type_ordinal(main_til, name)
        if ordinal != 0:
            newtype = ida_print_decl(ordinal)
        else:
            newtype = "ERROR: could not fetch type from main til"
            errors += 1
            print("Could not fetch new type with name %s from main til" % name)
        oldtype = types_backup.get(name)
        if oldtype is None:
            if t.get_forward_type() == 13:  # forward declaration
                num_unchanged += 1
            else:
                num_new += 1
        elif oldtype == newtype:
            num_unchanged += 1
        else:
            conflicts[name] = (oldtype, newtype)

    import datetime
    date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"type_conflicts-{date}.txt", "w") as f:
        for name, (oldtype, newtype) in conflicts.items():
            f.write(f"Conflict for type {name}:\n")
            f.write(f"Old: {oldtype}\n")
            f.write(f"New: {newtype}\n")
            f.write("\n")

    ida_kernwin.msg(f"""
    Importing types finished.
    errors: {errors}
    total types: {len(list(til.named_types()))}
    new: {num_new}
    unchanged: {num_unchanged}
    ignored: {num_ignored}
    conflicts: {len(conflicts)} (saved to {os.getcwd()}/type_conflicts-{date}.txt)
    """)
finally:
    progress.hide()

ida_typeinf.free_til(til)
