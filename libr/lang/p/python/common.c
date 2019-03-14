/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#include "common.h"

PyObject *getO(PyObject *o, const char *name) {
	if (!o) return NULL;
	PyObject *res = PyDict_GetItemString (o, name);
	if (!res) return NULL;
	return res;
}

char *getS(PyObject *o, const char *name) {
	if (!o) return NULL;
	PyObject *res = PyDict_GetItemString (o, name);
	if (!res) return NULL;
	return strdup (PyUnicode_AsUTF8 (res));
}

st64 getI(PyObject *o, const char *name) {
	if (!o) return 0;
	PyObject *res = PyDict_GetItemString (o, name);
	if (!res) return 0;
	return (st64) PyNumber_AsSsize_t (res, NULL);
}

void *getF(PyObject *o, const char *name) {
	if (!o) return NULL;
	return PyDict_GetItemString (o, name);
}

bool getB(PyObject *o, const char *name) {
	if (!o) return NULL;
	if (PyObject_IsTrue(o)) return true;
	return false;
}