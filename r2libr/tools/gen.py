
#!/usr/bin/python3
#
# This tool is intended for development only.

import subprocess
from argparse import ArgumentParser
from pathlib import Path
import sys
import re
import os

libs = [
    "anal",
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
    "hash",
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
    def _impl(dir: Path):
        includes.append(dir)
        for child in dir.iterdir():
            if child.is_dir() and child not in includes:
                _impl(child)
    include_root = Path(builddir) / "include" / "libr"
    includes = []
    _impl(include_root)
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
    #args += ['-x']
    args += ["-v"]
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
    # Convert the lib reference to imported r2lib.
    # e.g.
    # _libraries['libr_core.so.5.2.0-git'] => _libr_core
    for _lib in libs:
        binding_content = binding_content.replace(f"_libraries['{libs_path[_lib].name}']", f"_libr_{_lib}")
    # Import all r2libs.
    binding_content = binding_content.replace("import ctypes", "import ctypes\n" + "\n".join([f"from .r_libs import r_{_lib} as _libr_{_lib}" for _lib in libs]))
    # Remove the redundant assignment
    # e.g. 
    # _libr_core = ctypes.CDLL('/path/to/libr_core.so.5.2.0-git')
    for _lib in libs:
        binding_content = re.sub(rf".*ctypes.CDLL.*{libs_path[_lib].name}.*\n", "", binding_content)
    # Remove clang2py args in comments.
    # e.g.
    # TARGET arch is: ['arg1', 'arg2']
    binding_content = re.sub(rf".*TARGET arch is.*\n", "", binding_content)
    
    return binding_content

# We have to expand r_util manually.
# Note that we don't need to expand headers deeper since we only focus on R_API.
# FIXME: Any better approach?
def expand_util(pargs):
    r_util_path = Path(pargs.build) / "include" / "libr" / "r_util.h"
    r_util_gen_path = Path(pargs.build) / "include" / "libr" / "r_util_gen.h"
    with open(r_util_path, "r+") as f:
        content = f.read()
    sub_util_headers = re.findall(r'\n#include "(r_util/r_.*.h)"', content)
    sub_util_headers.extend(re.findall(r"#include <(r_.*h)>", content))
    output_util = ""
    generated_headers = set()
    for ln in content.splitlines(keepends=True):
        headers = re.findall(r'^#include "(r_util/r_.*.h)"', ln)
        if len(headers) == 0:
            headers = re.findall(r"^#include <(r_.*h)>", ln)
        if len(headers) == 0 and "r_util/r_print.h" in ln:
            all_utils = set([ f"r_util/{util}" for util in os.listdir(Path(pargs.build) / "include" / "libr" / "r_util")])
            headers = list(all_utils.difference(generated_headers))
            print("Going to generate the following utils which are not included in r_util.h")
            print("\n".join(headers))
        if len(headers) == 0:
            output_util += ln
        else:
            for header in headers:
                with open(Path(pargs.build) / "include" / "libr" / header) as f:
                    output_util += f.read()
                    output_util += "\n"
                generated_headers.add(header)
    with open(r_util_gen_path, "w+") as f:
        f.write(output_util)

def handle_lib(lib, pargs):
    if lib == "util":
        expand_util(pargs)
        fpath = str(Path(pargs.build) / "include" / "libr" / f"r_util_gen.h")
    else:
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
#parser.add_argument("-H", "--headers", help="r2 headers dir", type=str)
parser.add_argument("-B", "--build", help="meson install dir", type=str)
parser.add_argument("-L", "--lib", help="r2 lib name", type=str)
#parser.add_argument("-C", "--clang-args", help="clang args", type=str)
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