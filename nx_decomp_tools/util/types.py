import enum
import typing as tp

class FunctionStatus(enum.Enum):
    Matching = 0
    Equivalent = 1  # semantically equivalent but not perfectly matching
    NonMatching = 2
    Wip = 3
    NotDecompiled = 4


class FunctionInfo(tp.NamedTuple):
    addr: int  # without the 0x7100000000 base
    name: str
    size: int
    decomp_name: str
    library: bool
    status: FunctionStatus
    raw_row: tp.List[str]
