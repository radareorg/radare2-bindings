import libr
import ctypes
import argparse

class R2:

    def __init__(self, binary):
        binary = binary.encode("utf-8")
        self._r2c = libr.r_core.r_core_new()
        fh = libr.r_core.r_core_file_open(self._r2c, ctypes.create_string_buffer(binary), 0b101, 0)
        libr.r_core.r_core_bin_load(self._r2c, ctypes.create_string_buffer(binary), (1<<64) - 1)
    
    def cmd(self, cmd):
        r = libr.r_core.r_core_cmd_str(self._r2c, ctypes.create_string_buffer(cmd.encode("utf-8")))
        return ctypes.string_at(r).decode('utf-8')
    
    def __del__(self):
        libr.r_core.r_core_free(self._r2c)
    
if __name__ == "__main__":
    ap = argparse.ArgumentParser("Implement a basic command line r2 by r2libr")
    ap.add_argument("binary", help="The binary to analyse.")
    args = ap.parse_args()

    r2pipe = R2(args.binary)

    while True:
        print("> ", end="")
        cmd = input()
        if cmd.strip() == "q":
            break
        print(r2pipe.cmd(cmd))