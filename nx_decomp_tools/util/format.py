import sys
from colorama import Fore, Style
import typing as tp

def format_demangled_name(demangled: str, name: str) -> str:
    return f"{demangled} {Style.DIM}({name}){Style.RESET_ALL}"


def format_demangled_name_for_msg(demangled: str, name: str) -> str:
    return f"{Fore.BLUE}{demangled}{Fore.RESET} {Style.DIM}({name}){Style.RESET_ALL}{Style.BRIGHT}"


def print_note(msg: str, prefix: str = ""):
    sys.stderr.write(f"{Style.BRIGHT}{prefix}{Fore.CYAN}note:{Fore.RESET} {msg}{Style.RESET_ALL}\n")


def warn(msg: str, prefix: str = ""):
    sys.stderr.write(f"{Style.BRIGHT}{prefix}{Fore.MAGENTA}warning:{Fore.RESET} {msg}{Style.RESET_ALL}\n")


def print_error(msg: str, prefix: str = ""):
    sys.stderr.write(f"{Style.BRIGHT}{prefix}{Fore.RED}error:{Fore.RESET} {msg}{Style.RESET_ALL}\n")


def fail(msg: str, prefix: str = "") -> tp.NoReturn:
    print_error(msg, prefix)
    sys.exit(1)
