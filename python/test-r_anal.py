try:
	import os, signal
	from r_core import *
except:
	from r2.r_core import *

rc = RCore()
rc.file_open("/bin/ls", 0, 0)
rc.bin_load("", 0)

rc.anal_all()
funcs = rc.anal.get_fcns()

for f in funcs:
	blocks = f.get_bbs()
	print("+" + (72 * "-"))
	print("| FUNCTION: %s @ 0x%x" % (f.name, f.addr))
	print("| (%d blocks)" % (len (blocks)))
	print("+" + (72 * "-"))

	for b in blocks:
		print("---[ Block @ 0x%x ]---" % (b.addr))
		print("   | type:        %x" % (b.type))
		print("   | size:        %d" % (b.size))
		print("   | jump:        0x%x" % (b.jump))
		print("   | fail:        0x%x" % (b.fail))
		print("   | conditional: %d" % (b.conditional))
		print("   | return:      %d" % (b.returnbb))

		end_byte = b.addr + b.size
		cur_byte = b.addr

		while (cur_byte < end_byte):
			#anal_op = rc.op_anal(cur_byte)
			asm_op = rc.disassemble (cur_byte)
			if asm_op:
				if asm_op.size == 0:
					print("Bogus op")
					break

				print("0x%x %s" % (cur_byte, asm_op.buf_asm))
				#print("0x%x %s %s" % (cur_byte, asm_op.buf_hex, asm_op.buf_asm))
				cur_byte += asm_op.size
			else:
				print("Invalid at",f.addr);
				break

# RCore.fini() crashes when freeing fcnlist from python
# because it doublefrees some stuff, terminating the process
# ensures no RCore deinitialization is done, and therefor
# no doublefree happens. This must be fixed, but at least
# this way it allows people to use the API.
os.kill (os.getpid (), signal.SIGTERM)
