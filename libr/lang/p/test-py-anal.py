# Example Python Anal plugin written in Python
# ============================================
#
#  -- pancake @ nopcode.org
#
# The r2lang.plugin function exposes a way to register new plugins
# into the RCore instance. This API is only available from RLang.
# You must call with with '#!python test.py' or 'r2 -i test.py ..'

import r2lang

def pyasm(a):
	def assemble(s):
		print("Assembling %s"%(s))
		return [ 1, 2, 3, 4 ]

	def disassemble(buf, buflen, pc):
		try:
			return [ 2, f"opcode {buf[0]}" ]
		except:
			print("err")
			print(sys.exc_info())
			return [ 2, "opcode" ]
	return {
		"name": "MyPyDisasm",
		"arch": "pyarch",
		"bits": 32,
		"license": "GPL",
		"desc": "disassembler plugin in python",
		"assemble": assemble,
		"disassemble": disassemble,
	}

if not r2lang.plugin("asm", pyasm):
	print("Failed to register the python asm plugin.")
	
