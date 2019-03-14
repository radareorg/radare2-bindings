/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_COMMON_H
#define _PY_COMMON_H
#include <r_lib.h>
#include <r_lang.h>

#undef _GNU_SOURCE
#undef _XOPEN_SOURCE
#undef _POSIX_C_SOURCE
#undef PREFIX

#include <Python.h>
#include <structmember.h>

#if PY_MAJOR_VERSION<3
#error Python 2 support is deprecated, use Python 3 instead
#endif

typedef struct {
	PyObject_HEAD
	PyObject *first; /* first name */
	PyObject *last;  /* last name */
	int number;
} Radare;

PyObject *getO(PyObject *o, const char *name);

char *getS(PyObject *o, const char *name);

st64 getI(PyObject *o, const char *name);

void *getF(PyObject *o, const char *name);

bool getB(PyObject *o, const char *name);
#endif /* _PY_COMMON_H */