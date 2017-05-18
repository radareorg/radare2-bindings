/* radare - LGPL - Copyright 2009-2016 - pancake */

/* r_io */
static RIOPlugin *py_io_plugin = NULL;
static void *py_io_open_cb = NULL;
static void *py_io_check_cb = NULL;
static void *py_io_read_cb = NULL;
static void *py_io_system_cb = NULL;
static void *py_io_seek_cb = NULL;

static RIODesc* py_io_open(RIO *io, const char *path, int rw, int mode) {
	if (py_io_open_cb) {
		int fd = -1;
		PyObject *arglist = Py_BuildValue ("(zii)", path, rw, mode);
		PyObject *result = PyEval_CallObject (py_io_open_cb, arglist);
		if (result) {
			if (PyInt_Check (result)) {
				if (PyInt_AsLong (result) == -1) {
					return NULL;
				}
				fd = PyInt_AsLong (result);
			}
			if (PyBool_Check (result) && result == Py_False) {
				return NULL;
			}
		}
		return r_io_desc_new (py_io_plugin, fd, path, rw, mode, NULL);
	}
	return NULL;
}

static bool py_io_check(RIO *io, const char *path, bool many) {
	if (py_io_check_cb) {
		PyObject *arglist = Py_BuildValue ("(zO)", path, many?Py_True:Py_False);
		PyObject *result = PyEval_CallObject (py_io_check_cb, arglist);
		if (result && PyBool_Check (result)) {
			return result == Py_True;
		}
		// PyObject_Print(result, stderr, 0);
		eprintf ("CHECK: Unknown type returned. Boolean was expected.\n");
	}
	return false;
}

static ut64 py_io_seek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (py_io_seek_cb) {
		PyObject *arglist = Py_BuildValue ("(Ki)", offset, whence);
		PyObject *result = PyEval_CallObject (py_io_seek_cb, arglist);
		if (result && PyInt_Check (result)) {
			return io->off = PyInt_AsLong (result);
		}
		if (result && PyLong_Check (result)) {
			ut64 num = PyLong_AsLongLong (result);
			return io->off = num;
		}
		 PyObject_Print(result, stderr, 0);
		//eprintf ("SEEK Unknown type returned. Number was expected.\n");
		switch (whence) {
		case 0: return io->off = offset;
		case 1: return io->off += offset;
		case 2: return 512;
		}
		return -1;
	}
	return -1;
}

static int py_io_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (py_io_read_cb) {
		PyObject *arglist = Py_BuildValue ("(Ki)", io->off, count);
		PyObject *result = PyEval_CallObject (py_io_read_cb, arglist);
		if (result) {
			if (PyString_Check (result)) {
				int size = PyString_Size (result);
				int limit = R_MIN (size, count);
				memset (buf, io->Oxff, limit);
				memcpy (buf, PyString_AsString (result), limit);
				// eprintf ("result is a string DONE %d %d\n" , count, size);
				return limit;
			}
			if (PyList_Check (result)) {
				int i, size = PyList_Size (result);
				int limit = R_MIN (size, count);
				memset (buf, io->Oxff, count);
				for (i = 0; i < limit; i++) {
					PyObject *len = PyList_GetItem (result, i);
					buf[i] = PyNumber_AsSsize_t (len, NULL);
				}
				return count;
			}
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
		}
		return -1;
	}
	return -1;
}

static int py_io_system(RIO *io, RIODesc *desc, const char *cmd) {
	if (py_io_system_cb) {
		PyObject *arglist = Py_BuildValue ("(z)", cmd);
		PyObject *result = PyEval_CallObject (py_io_system_cb, arglist);
		if (result) {
			if (PyBool_Check (result)) {
				return result == Py_True;
			}
			if (PyInt_Check (result)) {
				return PyInt_AsLong (result);
			}
		}
		// PyObject_Print(result, stderr, 0);
		eprintf ("Unknown type returned. Boolean was expected.\n");
	}
	return -1;
}

static PyObject *Radare_plugin_io(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RIOPlugin *ap = R_NEW0 (RIOPlugin);
	if (!ap) {
		return Py_False;
	}
	py_io_plugin = ap;
	ap->name = getS (o,"name");
	ap->desc = getS (o, "desc");
	ap->license = getS (o, "license");

	ptr = getF (o, "open");
	if (ptr) {
		Py_INCREF (ptr);
		py_io_open_cb = (void*)ptr;
		ap->open = py_io_open;
	}
	ptr = getF (o, "check");
	if (ptr) {
		Py_INCREF (ptr);
		py_io_check_cb = (void*)ptr;
		ap->check = py_io_check;
	}
	ptr = getF (o, "read");
	if (ptr) {
		Py_INCREF (ptr);
		py_io_read_cb = (void*)ptr;
		ap->read = py_io_read;
	}
	ptr = getF (o, "system");
	if (ptr) {
		Py_INCREF (ptr);
		py_io_system_cb = (void*)ptr;
		ap->system = py_io_system;
	}
	ptr = getF (o, "seek");
	if (ptr) {
		Py_INCREF (ptr);
		py_io_seek_cb = (void*)ptr;
		ap->lseek = py_io_seek;
	}
#if 0
	ptr = getF (o, "close");
	ptr = getF (o, "write");
	ptr = getF (o, "resize");
#endif
	RLibStruct *lp = R_NEW0 (RLibStruct);
	lp->type = R_LIB_TYPE_IO;
	lp->data = ap;
	r_lib_open_ptr (core->lib, "python.py", NULL, lp);
	return Py_True;
}

