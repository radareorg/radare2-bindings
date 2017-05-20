# Example Python IO plugin written in Python
# ===========================================
#
#  -- pancake @ nopcode.org
#
# Usage:
#   r2 -I test-py-io.py pyio://33
#
# The r2lang.plugin function exposes a way to register new plugins
# into the RCore instance. This API is only available from RLang.
# You must call with with '#!python test.py' or 'r2 -i test.py ..'

import r2lang

FAKESIZE = 512

def pyio(a):
	def _open(path, rw, perm):
		print("MyPyIO Opening %s"%(path))
		return 1234 
	def _check(path, many):
		print("python-check %s"%(path))
		return path[0:7] == "pyio://"
	def _read(offset, size):
		print("python-read")
		return "A" * size
	def _seek(offset, whence):
		print("python-seek")
		if whence == 0: # SET
			return offset
		if whence == 1: # CUR
			return offset
		if whence == 2: # END
			return 512 
		return 512
	def _write(offset, data, size):
		print("python-write")
		return True
	def _system(cmd):
		print("python-SYSTEM %s"%(cmd))
		return True
	return {
		"name": "pyio",
		"license": "GPL",
		"desc": "IO plugin in python (pyio://3)",
		"check": _check,
		"open": _open,
		"read": _read,
		"seek": _seek,
		"write": _write,
		"system": _system,
	}

print("Registering Python IO plugin...")
print(r2lang.plugin("io", pyio))
