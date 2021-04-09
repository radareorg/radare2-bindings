import unittest
import ctypes
import libr
import json
import struct
import sys

if sys.platform == "win32":
    example_file = b"""C:\Windows\system32\cmd.exe"""
else:
    example_file = b"/bin/ls"

class R2LIBRTest(unittest.TestCase):
    
    def __get_r_core(self):
        r2c = libr.r_core.r_core_new()
        fh = libr.r_core.r_core_file_open(r2c, ctypes.create_string_buffer(example_file), 0b101, 0)
        libr.r_core.r_core_bin_load(r2c, ctypes.create_string_buffer(example_file), (1<<64) - 1)
        return r2c

    def test_r_core(self):
        r2c = self.__get_r_core()
        libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"ieq"))
        libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"aaa"))
        if sys.platform != "win32":
            print(f'Disasm 1 instruction:\n{ctypes.string_at(libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"pd 1"))).decode("utf-8")}')
        else:
            # CMD doesn't support colors.
            print(f'Disasm 1 instruction:\n{ctypes.string_at(libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"pdj 1"))).decode("utf-8")}')
        libr.r_core.r_core_free(r2c)

    def test_r_anal(self):
        r2c = self.__get_r_core()
        libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"ieq"))
        libr.r_core.r_core_cmd_str(r2c, ctypes.create_string_buffer(b"aaa"))
        # Workaround for multiple declarations in sources.
        r2anal = ctypes.cast(ctypes.addressof(r2c.contents.anal.contents), ctypes.POINTER(libr.r_anal.struct_r_anal_t))
        print(f"We have {libr.r_anal.r_anal_xrefs_count(r2anal)} xrefs!")

    def test_r_asm(self):
        buffer = b"\x90\x90\x90"
        buffer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        r2c = self.__get_r_core()
        r2asm = ctypes.cast(r2c.contents.rasm, ctypes.POINTER(libr.r_asm.struct_r_asm_t))
        asmcode = libr.r_asm.r_asm_mdisassemble(r2asm, buffer, 3)
        disasm_output = ctypes.string_at(asmcode.contents.assembly).decode('utf-8')
        self.assertEqual(disasm_output, "nop\nnop\nnop\n")

    def test_r_util_json(self):
        json_str = b'{"key" : "value"}'
        rjson = libr.r_util.r_json_parse(json_str)
        rjson = libr.r_util.r_json_get(rjson, b"key")
        value = ctypes.string_at(rjson.contents.str_value).decode("utf-8")
        self.assertEqual(value, "value")

    def test_r_util_utf8(self):
        u8 = '\u4e91'
        rune = ord(u8)
        buffer = ctypes.create_string_buffer(4)
        buffer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        l = libr.r_util.r_utf8_encode(buffer, ctypes.c_uint32(rune))
        self.assertEqual(ctypes.string_at(buffer, l), u8.encode("utf-8"))

if __name__ == "__main__":
    unittest.main()