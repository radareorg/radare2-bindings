/* radare - LGPL - Copyright 2016 - pancake */

#include <r_core.h>
#include <r_cmd.h>

/* TODO : move into a struct stored in the plugin struct */
static void *py_core_call_cb = NULL;

static int py_core_call(void *user, const char *str) {
	if (py_core_call_cb) {
		PyObject *arglist = Py_BuildValue ("(z)", str);
		PyObject *result = PyEval_CallObject (py_core_call_cb, arglist);
		if (result) {
			if (PyLong_Check (result)) {
				return PyLong_AsLong (result);
			} else if (PyInt_Check (result)) {
				return PyInt_AsLong (result);
			}
		}
	}
	return 0;
}

static PyObject *Radare_plugin_core(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RCorePlugin *ap = R_NEW0 (RCorePlugin);
	ap->name = getS (o, "name");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ptr = getF (o, "call");
	if (ptr) {
		Py_INCREF (ptr);
		py_core_call_cb = ptr;
		ap->call = py_core_call;
	}
	RLibStruct *lp = R_NEW0 (RLibStruct);
	lp->type = R_LIB_TYPE_CORE;
	lp->data = ap;
	r_lib_open_ptr (core->lib, "python.py", NULL, lp);
	return Py_True;
}
