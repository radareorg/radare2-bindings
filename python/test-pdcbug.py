import sys
try:
	from r_core import RCore
except:
	from r2.r_core import RCore
 
core = RCore()
#core.file_open("/bin/ls", False, 0)
 
# Detect sub-bins in fatmach0
path="/bin/ls"
#path="/bin/ls"
core.bin.load (path, 0, 0, 0, 0, 0)
# Load file in core
core.config.set ("asm.arch", "x86");
#core.config.set ("asm.bits", "32");
core.config.set ("asm.bits", "64");
 
f = core.file_open(path, False, 0)
#core.bin_load (None)
core.bin_load ("", 0)
 
a = core.cmd_str ("af @ entry0")
# show entrypoint
print ("Entrypoint : 0x%x"%(core.num.get ("entry0")))
print (core.cmd_str ("pd 12 @ entry0"))
 
a = core.cmd_str ("pdc @ entry0")
print a
