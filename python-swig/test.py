#!/usr/bin/env python3
# Smoke test for the hand-written SWIG bindings. No valabind involved.
import sys
import r_core

c = r_core.r_core_new()
if not c:
    print("r_core_new failed", file=sys.stderr)
    sys.exit(1)

version = r_core.r_core_cmd_str(c, "?V")
print("radare2 version:", (version or "").strip())

r_core.r_core_cmd0(c, "o malloc://32")
r_core.r_core_cmd0(c, "e asm.arch=x86")
r_core.r_core_cmd0(c, "e asm.bits=64")
r_core.r_core_cmd0(c, "e scr.color=0")
r_core.r_core_cmd0(c, "wx 4889e5")
disasm = r_core.r_core_cmd_str(c, "pd 1")
print("disasm:", (disasm or "").strip())

offset = r_core.r_core_get_offset(c)
print("offset: 0x%x" % offset)

r_core.r_core_free(c)
print("OK")
