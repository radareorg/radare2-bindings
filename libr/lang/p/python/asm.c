/* radare - LGPL - Copyright 2009-2019 - pancake */

#include "asm.h"
#include "core.h"

/* TODO : move into a struct stored in the plugin struct */
static void *py_assemble_cb = NULL;
static void *py_disassemble_cb = NULL;

static int check_list_result(PyObject *result, const char *fcn_name) {
	if (!result) {
		eprintf ("Error while calling %s in Python\n", fcn_name);
		PyErr_Print ();
		return 0;
	}
	if (!PyList_Check (result)) {
		PyObject *str = PyObject_Str (result);
		Py_DECREF (result);
		if (!str) {
			PyErr_Print ();
		} else {
			if (PyUnicode_Check (str)) {
				eprintf ("Unknown type returned from %s. List was expected, got %s.\n", fcn_name, PyUnicode_AsUTF8 (str));
			} else {
				eprintf ("Unknown type returned from %s. List was expected.\n", fcn_name);
			}
			Py_DECREF (str);
		}
		return 0;
	}
	return 1;
}

static int py_assemble(RAsm *a, RAsmOp *op, const char *str) {
	int i, size = 0;
	int seize = -1;
	const char *opstr = str;
	ut8 *buf = (ut8*)r_strbuf_get (&op->buf);
	if (py_assemble_cb) {
		PyObject *arglist = Py_BuildValue ("(zK)", str, a->pc);
		PyObject *result = PyEval_CallObject (py_assemble_cb, arglist);
		if (check_list_result (result, "assemble")) {
			seize = size = PyList_Size (result);
			for (i = 0; i < size ; i++) {
				PyObject *len = PyList_GetItem (result, i);
				buf[i] = PyNumber_AsSsize_t (len, NULL);
			}
			Py_DECREF (result);
		}
	}
	op->size = size = seize;
	r_strbuf_set (&op->buf_asm, opstr);
	//r_hex_bin2str ((ut8*)r_strbuf_get (&op->buf), op->size, r_strbuf_get (&op->buf_hex));
	return seize;
}

static int py_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int size = 0;
	int seize = -1;
	r_asm_op_init (op);
	r_strbuf_set (&op->buf_asm, "invalid");
	if (py_disassemble_cb) {
		Py_buffer pybuf = {
			.buf = (void *) buf, // Warning: const is lost when casting
			.len = len,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1,
		};
		PyObject *memview = PyMemoryView_FromBuffer (&pybuf);
		PyObject *arglist = Py_BuildValue ("(NK)", memview, a->pc);
		PyObject *result = PyEval_CallObject (py_disassemble_cb, arglist);
		if (check_list_result (result, "disassemble")) {
			PyObject *pylen = PyList_GetItem (result, 0);
			PyObject *pystr = PyList_GetItem (result, 1);
			seize = PyNumber_AsSsize_t (pylen, NULL);
			r_strbuf_set (&op->buf_asm, PyUnicode_AsUTF8 (pystr));
			Py_DECREF (result);
		}
	}
	op->size = size = seize;
	int buflen = R_MAX (1, op->size);
	buflen = R_MIN (buflen, len);
	char *res = calloc (buflen, 3);
	if (res) {
		r_asm_op_set_buf (op, buf, buflen);
		free (res);
	}
	return seize;
}

void Radare_plugin_asm_free(RAsmPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->arch);
	free ((char *)ap->license);
	free ((char *)ap->desc);
	free (ap);
}

PyObject *Radare_plugin_asm(Radare* self, PyObject *args) {
	PyObject *arglist = Py_BuildValue ("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RAsmPlugin *ap = R_NEW0 (RAsmPlugin);
	if (!ap) {
		return NULL;
	}
	ap->name = getS (o,"name");
	ap->arch = getS (o, "arch");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ap->bits = getI (o, "bits");
	ap->endian = getI (o, "endian");
	void *ptr = getF (o, "disassemble");
	if (ptr) {
		Py_INCREF (ptr);
		py_disassemble_cb = ptr;
		ap->disassemble = py_disassemble;
	}
	ptr = getF (o, "assemble");
	if (ptr) {
		Py_INCREF (ptr);
		py_assemble_cb = ptr;
		ap->assemble = py_assemble;
	}
	Py_DECREF (o);

	RLibStruct lp = {0};
	lp.type = R_LIB_TYPE_ASM;
	lp.data = ap;
	lp.free = (void (*)(void *data))Radare_plugin_asm_free;
	r_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
