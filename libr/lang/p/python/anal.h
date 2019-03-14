/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_ANAL_H
#define _PY_ANAL_H

#include <r_anal.h>
#include "common.h"

void py_export_anal_enum(PyObject *tp_dict);

void Radare_plugin_anal_free(RAnalPlugin *ap);

PyObject *Radare_plugin_anal(Radare* self, PyObject *args);

#endif /* _PY_ANAL_H */