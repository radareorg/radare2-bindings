## r2api

Yet another radare2 python bindings.

Compared to [radare2-bindings](https://github.com/radareorg/radare2-bindings/python) and [radare2-r2pipe](https://github.com/radareorg/radare2-r2pipe), this binding:

- Doesn't need any extra installation of radare2. Just `pip install` and you are ready to go.
- Gives you the full control of the core radare2 API and helps build your own tools.

## Install

```bash
pip3 install --upgrade r2api
```

**No need to install radare2** since all dynamic libraries are bundled with the Python wheels.

## Example

Implement a basic command line r2 by r2api.

```python
import r2
import ctypes
import argparse

class R2:

    def __init__(self, bin):
        self._r2c = r2.r_core.r_core_new()
        fh = r2.r_core.r_core_file_open(self._r2c, ctypes.create_string_buffer(b"/bin/ls"), 0b101, 0)
        r2.r_core.r_core_bin_load(self._r2c, ctypes.create_string_buffer(b"/bin/ls"), (1<<64) - 1)
    
    def cmd(self, cmd):
        r = r2.r_core.r_core_cmd_str(self._r2c, ctypes.create_string_buffer(cmd.encode("utf-8")))
        return ctypes.string_at(r).decode('utf-8')
    
    def __del__(self):
        r2.r_core.r_core_free(self._r2c)
    
if __name__ == "__main__":
    ap = argparse.ArgumentParser("Implement a basic command line r2 by r2api")
    ap.add_argument("binary", help="The binary to analyse.")
    args = ap.parse_args()

    r2pipe = R2(args.binary)

    while True:
        print("> ", end="")
        cmd = input()
        if cmd.strip() == "q":
            break
        print(r2pipe.cmd(cmd))
```

Note that all radare2 APIs are exported as bare ctypes function prototype. Be catious with c-style strings.

## Build Instructions

Clone the repository.

```bash
git clone https://github.com/radareorg/radare2-bindings
cd radare2-bindings/r2api
```

Since radare2 chooses `meson` as their alternative building system and it's cross-platform, the first step is install `meson`.

```bash
pip3 install meson
```

Build the package. Note that on Windows, `x64 Native Tools Command Prompt` is required to build.

```bash
python3 setup.py build
```

Install and use.

```bash
# Or pip3 install -e .
pip3 install .
```

## Credits

- [radare2](https://github.com/radareorg/radare2): Awesome project.
- [ctypeslib](https://github.com/trolldbois/ctypeslib): Bindings generation.
