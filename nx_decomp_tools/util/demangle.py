from .format import warn, format_demangled_name, format_demangled_name_for_msg

try:
    import cxxfilt
    _demangler = cxxfilt.demangle
except:
    # cxxfilt cannot be used on Windows.
    warn("cxxfilt could not be imported; demangling functions will fail")
    _demangler = None

def demangle(name: str) -> str:
    try:
        if _demangler is not None:
            return _demangler(name)
    except:
        pass
    return name

def are_demangled_names_equal(name1: str, name2: str):
    return demangle(name1) == demangle(name2)

def format_symbol_name(name: str) -> str:
    return format_demangled_name(demangle(name), name)

def format_symbol_name_for_msg(name: str) -> str:
    return format_demangled_name_for_msg(demangle(name), name)
