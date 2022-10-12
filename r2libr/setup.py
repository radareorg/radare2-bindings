import setuptools
import sys
import os
import subprocess
import shutil
import struct
import re
import platform
from distutils.util import get_platform
from distutils.command.build import build as _build
from distutils.command.sdist import sdist as _sdist
from setuptools.command.bdist_egg import bdist_egg as _bdist_egg
from setuptools.command.develop import develop as _develop
from distutils.command.clean import clean as _clean
from pathlib import Path

IS_64BITS = platform.architecture()[0] == '64bit'

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
RADARE2_DIR = Path(ROOT_DIR) / "radare2"
LIBS_DIR = Path(ROOT_DIR) / "libr" / "libr"

def detect_python_on_windows():
    try:
        p = subprocess.run('python -c "import sys;print(sys.version_info.major)"', capture_output=True)
        output = p.stdout.decode("utf-8")
        if int(output) == 3:
            return ["python"]
    except FileNotFoundError:
        pass
    try:
        p = subprocess.run('py -3 --version')
        if p.returncode == 0:
            return ["py", "-3"]
    except FileNotFoundError:
        pass
    return None

def clean_builds():
    shutil.rmtree(Path(ROOT_DIR) / "build", ignore_errors=True)
    shutil.rmtree(Path(ROOT_DIR) / "libr" / "libr", ignore_errors=True)
    shutil.rmtree(Path(ROOT_DIR) / "radare2" / "pyr2installdir", ignore_errors=True)
    shutil.rmtree(Path(ROOT_DIR) / "radare2" / "pyr2build", ignore_errors=True)

def radare2_exists():
    return (Path(ROOT_DIR) / "radare2" / ".git").exists()

def meson_exists_old():
    try:
        import mesonbuild
        return True
    except ImportError:
        return False

def meson_exists():
    if os.system("meson --version") == 0:
        return True
    return False

# Meson seems not to play well with macOS and radare2
# assumes that users will install the whole project to system.
# So we have to rewite all lib load path for our bindings.
# Refs:
# - https://github.com/mesonbuild/meson/issues/2121
def rewrite_dyld_path(dylib: Path):
    def _read_until_zero(fp):
        cur = fp.tell()
        s = b""
        ch = fp.read(1)
        while ch != b'\x00' and ch != b'':
            s += ch
            ch = fp.read(1)
        fp.seek(cur, 0)
        return s.decode("utf-8")
    def _parse_libr_name(path):
        result = re.findall(r"(libr_.*\.dylib$)", path)
        if len(result) == 0:
            return None
        else:   
            return result[0]
    def _verbose_call(*args, **kwargs):
        print(f"Calling: {args[0]}")
        return subprocess.call(*args, **kwargs)
    with open(dylib, "rb+") as f:
        magic = f.read(4)
        if magic != b'\xcf\xfa\xed\xfe':
            return
        _, _, _, load_num = struct.unpack("<IIII", f.read(16))

        # Skip file header
        f.seek(0x20, 0)

        for _ in range(load_num):
            section_start_pos = f.tell()
            section_header = f.read(8)
            if len(section_header) != 8:
                break
            cmd, size = struct.unpack("<II", section_header)
            # LC_ID_DYLIB
            if cmd == 0xD:
                offset, = struct.unpack("<I", f.read(4))
                f.seek(section_start_pos + offset, 0)
                id_dylib = _read_until_zero(f)
                lib_name = _parse_libr_name(id_dylib)
                if lib_name is not None:
                    print(f"Patching ID_DYLIB {id_dylib} for {str(dylib)}")
                    _verbose_call(["install_name_tool", "-id", f"@loader_path/{lib_name}", str(dylib)])
            # LC_LOAD_DYLIB
            elif cmd==0xC:
                offset, = struct.unpack("<I", f.read(4))
                f.seek(section_start_pos + offset, 0)
                load_dylib = _read_until_zero(f)
                lib_name = _parse_libr_name(load_dylib)

                # Why not @rpath?
                # Some refs:
                # - http://developer.apple.com/library/mac/#documentation/Darwin/Reference/Manpages/man1/dyld.1.html
                # - https://stackoverflow.com/questions/16826922/what-path-does-loader-path-resolve-to
                # - https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
                # Some notes for myself:
                #     The @rpath of the dylib comes from the application which loads it, not the dylib itself.
                if lib_name is not None:
                    print(f"Patching LOAD_DYLIB {lib_name} for {str(dylib)}")
                    _verbose_call(["install_name_tool", "-change", load_dylib, f"@loader_path/{lib_name}", str(dylib)])
            f.seek(section_start_pos + size, 0)
    return


def build_radare2():
    if not radare2_exists():
        raise RuntimeError("Fail to detect radare2 repository. Do you forget to init submodules?")
    if not meson_exists():
        raise RuntimeError("Fail to detect meson. Do you forget to install meson?")
    os.chdir(RADARE2_DIR)

    DEBUG = os.getenv("DEBUG", "")
    BUILDDIR = os.getenv("R2BUILDDIR", "pyr2build")
    PREFIX = os.getenv("R2PREFIX", str(Path(ROOT_DIR) / "radare2" / "pyr2installdir"))
    # if sys.platform == "win32":
    #     BACKEND = os.getenv("BACKEND", "vs2019")
    # else:
    BACKEND = os.getenv("BACKEND", "ninja")

    args = []
    if sys.platform == "win32":
        py = detect_python_on_windows()
        if py is None:
            raise RuntimeError("Can't find a python in your path!")
        args += py
    else:
        args += ['python3']
    args += ["./sys/meson.py"]
    if not DEBUG:
        args += ["--release"]
    args += ["--local"]
    args += ["--dir", BUILDDIR]
    args += ["--shared"]
    args += ["--backend", BACKEND]
    args += ["--prefix", PREFIX]
    args += ["--install"]
    # On Windows, there is no ptrace so we shouldn't generate such symbols.
    args += ["--options", "debugger=false", "sdb_cgen=false"]

    subprocess.call(args)
    if LIBS_DIR.exists():
        shutil.rmtree(LIBS_DIR)
    os.makedirs(LIBS_DIR, exist_ok=True)

    lib_install_dir = Path(PREFIX) / "bin" if sys.platform == "win32" else Path(PREFIX) / "lib"
    glob = {
        "linux" : "*.so*",
        "win32" : "*.dll",
        "darwin" : "*.dylib"
    }.get(sys.platform, "*.so")
    for p in lib_install_dir.rglob(glob):
        if p.is_file():
            if sys.platform == "darwin" and not p.is_symlink():
                rewrite_dyld_path(p)
            # Known Issue: Altough we copy symlinks here, still python would follow symlink and copy a duplicate one.
            #              To keep r_libs.py simple (meson write versions to file names), let's keep that copy.
            shutil.copy(p, LIBS_DIR, follow_symlinks=False)
    os.chdir(ROOT_DIR) 


class build(_build):
    def run(self):
        build_radare2()
        return _build.run(self)

class clean(_clean):
    def run(self):
        clean_builds()
        return _clean.run(self)

class develop(_develop):
    def run(self):
        build_radare2()
        return _develop.run(self)

class bdist_egg(_bdist_egg):
    def run(self):
        self.run_command('build')
        return _bdist_egg.run(self)

# https://stackoverflow.com/questions/45150304/how-to-force-a-python-wheel-to-be-platform-specific-when-building-it
# https://github.com/unicorn-engine/unicorn/blob/198e432a1d7edbed6f4726acc42c50c3a4141b6b/bindings/python/setup.py#L229
if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    idx = sys.argv.index('bdist_wheel') + 1
    sys.argv.insert(idx, '--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        # see https://github.com/pypa/manylinux
        # see also https://github.com/angr/angr-dev/blob/master/bdist.sh
        sys.argv.insert(idx + 1, 'manylinux1_' + platform.machine())
    elif 'mingw' in name:
        if IS_64BITS:
            sys.argv.insert(idx + 1, 'win_amd64')
        else:
            sys.argv.insert(idx + 1, 'win32')
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.insert(idx + 1, name.replace('.', '_').replace('-', '_'))

with open(Path(ROOT_DIR) / "README.md", "r+") as f:
    long_description = f.read()

setuptools.setup(
    name="r2libr",
    version="5.7.4",
    author="mio",
    author_email="mio@lazym.io",
    description="Yet anohter radare2 python bindings.",
    long_description=long_description,
    url="https://github.com/radareorg/radare2-bindings/tree/master/r2libr",
    packages=setuptools.find_packages(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3"
    ],
    cmdclass={
        "build" : build,
        "develop" : develop,
        "bdist_egg" : bdist_egg,
        "clean" : clean
    },
    python_requires='>=3.6',
    include_package_data=True,
    is_pure=False,
    package_data= {
        "libr" : ['libr/*']
    }
)

