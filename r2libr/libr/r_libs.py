import distutils.sysconfig
import pkg_resources
import sys
import os
import ctypes
from pathlib import Path

_libr_name = [
    "r_anal",
    "r_asm",
    "r_bin",
    "r_bp",
    "r_config",
    "r_cons",
    "r_core",
    "r_crypto",
    "r_debug",
    "r_egg",
    "r_flag",
    "r_fs",
    "r_hash",
    "r_io",
    "r_lang",
    "r_magic",
    "r_main",
    "r_parse",
    "r_reg",
    "r_search",
    "r_socket",
    "r_syscall",
    "r_util",
]

# https://stackoverflow.com/a/13874620/7510582
_fname_trans = { 'darwin': lambda x: f"lib{x}.dylib",
                 'win32': lambda x: f"{x}.dll",
                 'linux': lambda x: f"lib{x}.so",
                 'linux2': lambda x: f"lib{x}.so"}

_libraries = None

try:
    _trans = _fname_trans[sys.platform]
except KeyError:
    raise ImportError(f"Your platform {sys.platform} is not supported!")

_libr_fname = [_trans(_name) for _name in _libr_name]

_libr_fname_reverse_dict = { _trans(_name) : _name for _name in _libr_name}

_search_path = [Path(os.path.dirname(os.path.abspath(__file__))) / "libr",
                Path('') / "libr",
                Path("/usr/local/lib/") if sys.platform == 'darwin' else Path('/usr/lib64')]

# Workaround for dll dependencies.
# In Py3.8, we have a better way to do this.
def _load_libr_all(directory: Path):
    changed = True
    loaded = set()
    loaded_dlls = {}
    while changed:
        changed = False
        for p in directory.iterdir():
            if p in loaded:
                continue
            if p.is_file() and p.name.endswith("dll"):
                try:
                    loaded_dlls[p.name] = ctypes.cdll.LoadLibrary(str(p))
                    if p not in loaded:
                        changed = True
                        loaded.add(p)
                except OSError:
                    pass
    return loaded_dlls

def _load_libr(directory: Path, libr_fname: str):
    libr_path = directory / libr_fname
    try:
        return ctypes.cdll.LoadLibrary(str(libr_path))
    except OSError:
        return None

def _try_path(directory: Path):
    if sys.platform == "win32":
        return _load_libr_all(directory)
    result = {}
    for fname in _libr_fname:
        result[fname] = _load_libr(directory, fname)
    return result

def _check_libraries(libraries: dict):
    for fname in _libr_fname:
        if fname not in libraries or libraries[fname] is None:
            return False
    return True

for _path in _search_path:
    _result = _try_path(_path)
    if _check_libraries(_result):
        _libraries = { _libr_fname_reverse_dict[k] : v for k,v in _result.items() }
        break

if _libraries is None:
    raise ImportError("Libr is not found on your system or your libr installation is corrupted.")

r_anal = _libraries["r_anal"]
r_asm = _libraries["r_asm"]
r_bin = _libraries["r_bin"]
r_bp = _libraries["r_bp"]
r_config = _libraries["r_config"]
r_cons = _libraries["r_cons"]
r_core = _libraries["r_core"]
r_crypto = _libraries["r_crypto"]
r_debug = _libraries["r_debug"]
r_egg = _libraries["r_egg"]
r_flag = _libraries["r_flag"]
r_fs = _libraries["r_fs"]
r_hash = _libraries["r_hash"]
r_io = _libraries["r_io"]
r_lang = _libraries["r_lang"]
r_magic = _libraries["r_magic"]
r_main = _libraries["r_main"]
r_parse = _libraries["r_parse"]
r_reg = _libraries["r_reg"]
r_search = _libraries["r_search"]
r_socket = _libraries["r_socket"]
r_syscall = _libraries["r_syscall"]
r_util = _libraries["r_util"]