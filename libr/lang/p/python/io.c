/* radare - LGPL - Copyright 2009-2019 - pancake */

#include "io.h"
#include "core.h"

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
			if (PyLong_Check (result)) {
				if (PyLong_AsLong (result) == -1) {
					Py_DECREF (arglist);
					Py_DECREF (result);
					return NULL;
				}
				fd = (int)PyLong_AsLong (result);
			}
			if (PyBool_Check (result) && result == Py_False) {
				Py_DECREF (arglist);
				Py_DECREF (result);
				return NULL;
			}
		}
		Py_DECREF (arglist);
		Py_DECREF (result);
		return r_io_desc_new (io, py_io_plugin, path, rw, mode, NULL);
	}
	return NULL;
}

static bool py_io_check(RIO *io, const char *path, bool many) {
	bool res = false;
	if (py_io_check_cb) {
		PyObject *arglist = Py_BuildValue ("(zO)", path, many?Py_True:Py_False);
		PyObject *result = PyEval_CallObject (py_io_check_cb, arglist);
		if (result && PyBool_Check (result)) {
			res = result == Py_True;
		}
		Py_DECREF (arglist);
		Py_DECREF (result);
	}
	return res; 
}

static ut64 py_io_seek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (py_io_seek_cb) {
		PyObject *arglist = Py_BuildValue ("(Ki)", offset, whence);
		PyObject *result = PyEval_CallObject (py_io_seek_cb, arglist);
		if (result && PyLong_Check (result)) {
			return io->off = PyLong_AsLong (result);
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
	if (!py_io_read_cb) {
		return -1;
	}
	PyObject *arglist = Py_BuildValue ("(Ki)", io->off, count);
	PyObject *result = PyEval_CallObject (py_io_read_cb, arglist);
	if (result) {
		if (PyByteArray_Check (result)) {
			const char *ptr = PyByteArray_AsString (result);
			ssize_t size = PyByteArray_Size (result);
			ssize_t limit = R_MIN (size, (ssize_t)count);
			memset (buf, io->Oxff, limit);
			memcpy (buf, ptr, limit);
			count = (int)limit;
		} else if (PyUnicode_Check (result)) {
			//  PyObject* repr = PyObject_Repr(result);
			//  PyObject* str = PyUnicode_AsEncodedString(repr, "utf-8", "~E~");
			ssize_t size;
			const char *ptr = PyUnicode_AsUTF8AndSize (result, &size);
			ssize_t limit = R_MIN (size, (ssize_t)count);
			memset (buf, io->Oxff, limit);
			memcpy (buf, ptr, limit);
			count = (int)limit;
		} else if (PyBytes_Check (result)) {
			size_t size = PyBytes_Size (result);
			size_t limit = R_MIN (size, (size_t)count);
			memset (buf, io->Oxff, limit);
			memcpy (buf, PyBytes_AS_STRING (result), limit);
			// eprintf ("result is a string DONE %d %d\n" , count, size);
			count = (int)limit;
		} else if (PyList_Check (result)) {
			int i, size = PyList_Size (result);
			int limit = R_MIN (size, count);
			memset (buf, io->Oxff, count);
			for (i = 0; i < limit; i++) {
				PyObject *len = PyList_GetItem (result, i);
				buf[i] = PyNumber_AsSsize_t (len, NULL);
			}
			count = (int)limit;
		}
	} else {
		eprintf ("Unknown type returned. List was expected.\n");
	}
	Py_DECREF (arglist);
	Py_DECREF (result);
	return count;
}

static char *py_io_system(RIO *io, RIODesc *desc, const char *cmd) {
	char * res = NULL;
	if (py_io_system_cb) {
		PyObject *arglist = Py_BuildValue ("(z)", cmd);
		PyObject *result = PyEval_CallObject (py_io_system_cb, arglist);
		if (result) {
			if (
			PyUnicode_Check (result)
			) {
				res = PyBytes_AS_STRING (result);
			} else if (PyBool_Check (result)) {
				res = strdup (r_str_bool (result == Py_True));
			} else if (PyLong_Check (result)) {
				long n = PyLong_AsLong (result);
				res = r_str_newf ("%ld", n);
			}
		}
		// PyObject_Print(result, stderr, 0);
		eprintf ("Unknown type returned. Boolean was expected.\n");
		Py_DECREF (arglist);
		Py_DECREF (result);
	}
	return res;
}

void Radare_plugin_io_free(RIOPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->desc);
	free ((char *)ap->license);
	free (ap);
}

PyObject *Radare_plugin_io(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RIOPlugin *ap = R_NEW0 (RIOPlugin);
	if (!ap) {
		return Py_False;
	}
	py_io_plugin = ap;
	ap->name = getS (o, "name");
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
	Py_DECREF (o);

	RLibStruct lp = {};
	lp.type = R_LIB_TYPE_IO;
	lp.data = ap;
	lp.free = (void (*)(void *data))Radare_plugin_io_free;
	r_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}

