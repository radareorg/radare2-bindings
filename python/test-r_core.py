#!/usr/bin/env python3
#
# Python example for using loading fatmach0 binaries
# test file:
#   http://radare.org/get/bin/fatmach0-3true
import sys
try:
	from r_core import RCore
except:
	from r2.r_core import RCore

core = RCore()
#core.file_open("/bin/ls", False, 0)

# Detect sub-bins in fatmach0
path="/tmp/fatmach0-3true"
#path="/bin/ls"
core.bin.load (path, 0, 0, 0, 0, 0)
print ("Supported archs: %d"%core.bin.narch)

if core.bin.narch>1:
	for i in range (0,core.bin.narch):
		core.bin.select_idx (i)
		info = core.bin.get_info ()
		if info:
			print ("%d: %s %s"%(i,info.arch,info.bits))

# Load file in core
core.config.set ("asm.arch", "x86");
core.config.set ("asm.bits", "32");
#core.config.set ("asm.bits", "64");

f = core.file_open(path, False, 0)
#core.bin_load (None)
core.bin_load ("", 0)

print ("33+3 = ",core.num.math("33+3"));

# show entrypoint
print ("Entrypoint : 0x%x"%(core.num.get ("entry0")))
print (core.cmd_str ("pd 12 @ entry0"))
