#!/usr/bin/python
from r_bin import *
import ctypes

a = RBin()
if not a.load(b"/bin/ls", 0, 0, False):
	print("Fuck. cannot load /bin/ls")
	exit(1)

print ("------")
info = a.get_info ()
print ("type: "+info.type.decode())
print ("arch: "+info.arch.decode())
print ("mach: "+info.machine.decode())
print ("os: "+info.os.decode())
print ("subsys: "+info.subsystem.decode())

print ("------")

o = a.get_object ()
print ("object: "+str(o))

baddr = a.get_baddr()
print ("base address: "+str(baddr))
print ("------")

for s in a.get_sections():
	print("%s %d" % (s.name.decode(),s.rva))

exit(0)
