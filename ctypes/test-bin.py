#!/usr/bin/python
from r2.r_bin import *
import ctypes

#io = RIO()

path="/bin/ls"

#desc = io.open(path, 0, 0)
#if not desc:
#	print ("Damn")
#	exit(1)
#print("fuck",desc)
#print("FD = ",desc.fd)

a = RBin()
# --- failed a.iobind(io)
if not a.load(path, 0, 0, 0, -1, False):
	print("Fuck. cannot load /bin/ls")
	exit(1)

print ("------")
info = a.get_info ()
print ("type: ",info.type)

print ("arch: ",info.arch)
print ("mach: ",info.machine)
print ("os: ",info.os)
print ("subsys: ",info.subsystem)

print ("------")

o = a.get_object ()
print ("object: "+str(o))

baddr = a.get_baddr()
print ("base address: "+str(baddr))
print ("------")

for s in a.get_sections():
	print("%s %d" % (s.name.decode(),s.vaddr))

exit(0)
