#!/usr/bin/python3
#
# This tool is intended for development only.

import subprocess
from argparse import ArgumentParser
from pathlib import Path
import sys
import re
import os
import keyword

libs = [
    "anal",
    "arch",
    "asm",
    "bin",
    "bp",
    "config",
    "cons",
    "core",
    "crypto",
    "debug",
    "egg",
    "flag",
    "fs",
    "io",
    "lang",
    "magic",
    "main",
    "parse",
    "reg",
    "search",
    "socket",
    "syscall",
    "util",
]

def gen_clang_include_args(builddir):
    includes = []
    def _impl(dir: Path):
        includes.append(dir)
        for child in dir.iterdir():
            if child.is_dir() and child not in includes:
                _impl(child)
    _impl(Path(builddir) / "include" / "libr")
    return [f"-I{str(p.resolve())}" for p in includes]

def verbose_call(*args, **kwargs):
    print(" ".join([f'"{a}"' for a in args[0]]))
    return subprocess.run(*args, **kwargs)

def find_lib(builddir, lib_name):
    libr_path = Path(builddir) / "lib"
    for p in libr_path.rglob(f"libr_{lib_name}.so*"):
        if not p.is_symlink():
            return p
    return None

def clang2py_common_args(pargs):
    args = ["clang2py"]
    args += ["-v"]
    args += ["-i"]
    print(libs_path)
    for _, v in libs_path.items():
        args += ["-l", str(v.resolve())]
    clang_args = gen_clang_include_args(pargs.build)
    args += ["--clang-args", " ".join(clang_args)]
    return args

def clang2py_parse_header(pargs, header_path):
    args = clang2py_common_args(pargs)
    args += [header_path]
    p = verbose_call(args, stdout=subprocess.PIPE)
    return p.stdout.decode("utf-8")

def post_handle(binding_content, lib_name):
    for _lib in libs:
        binding_content = binding_content.replace(f"_libraries['{libs_path[_lib].name}']", f"_libr_{_lib}")
    binding_content = binding_content.replace("import ctypes", "import ctypes\n" + "\n".join([f"from .r_libs import r_{_lib} as _libr_{_lib}" for _lib in libs]))
    for _lib in libs:
        binding_content = re.sub(rf".*ctypes.CDLL.*{libs_path[_lib].name}.*\n", "", binding_content)
    binding_content = re.sub(rf".*TARGET arch is.*\n", "", binding_content)
    for kw in keyword.kwlist:
        binding_content = re.sub(rf'(?<!\w){kw}(\s*=\s*_libraries)', rf'{kw}_\1', binding_content)
        binding_content = re.sub(rf'(?<!\w){kw}\.(restype|argtypes)', rf'{kw}_.\1', binding_content)
        binding_content = re.sub(rf"_libraries\['([^']+)'\]\.{kw}(?!\w)", rf"_libraries['\1'].{kw}_", binding_content)
        binding_content = binding_content.replace(f"'{kw}'", f"'{kw}_'")

    return binding_content

def handle_lib(lib, pargs):
    fpath = str(Path(pargs.build) / "include" / "libr" / f"r_{lib}.h")
    binding = clang2py_parse_header(pargs, fpath)
    binding = post_handle(binding, lib)
    with open(Path(pargs.output) / f"r_{lib}.py", "w+") as f:
        f.write(binding)

def handle_init(pargs):
    root_init_path = Path(pargs.output) / "__init__.py"
    with open(Path(pargs.output) / "__init__.py", "w+") as f:
        f.write("\n".join([f"from .r_{_lib} import *" for _lib in libs]))

parser = ArgumentParser("r2 python bindings generator")
parser.add_argument("-O", "--output", help="output dir", type=str)
parser.add_argument("-B", "--build", help="meson install dir", type=str)
parser.add_argument("-L", "--lib", help="r2 lib name", type=str)
pargs = parser.parse_args()

libs_path = {}
for lib in libs:
    libs_path[lib] = find_lib(pargs.build, lib)

if pargs.lib is not None:
    if pargs.lib not in libs:
        print("Valid libs:" + " ".join(libs))
        exit(0)
    handle_lib(pargs.lib, pargs)
else:
    for lib in libs:
        handle_lib(lib, pargs)
    handle_init(pargs)
