#!/usr/bin/env python3
import sys
import time
import r2pipe

r2 = r2pipe.open()
pc = int(r2.cmd("dr?PC"), 0)
print(pc)
if pc == 0x100000f71:
	print ("CALLING PRINTF")
	r2.cmd("dr rax=0")
	sys.exit(1)

if pc == 0x1000012b0:
	print ("calls atoi")
	r2.cmd("dr rax=4")
	sys.exit(1)

sys.exit(0)
