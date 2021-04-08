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
    ap = argparse.ArgumentParser("Implement a basic command line r2 by pyr2")
    ap.add_argument("binary", help="The binary to analyse.")
    args = ap.parse_args()

    r2pipe = R2(args.binary)

    while True:
        print("> ", end="")
        cmd = input()
        if cmd.strip() == "q":
            break
        print(r2pipe.cmd(cmd))