/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_BIN_H
#define _PY_BIN_H

#include <r_bin.h>
#include "common.h"

PyObject *init_pybinfile_module(void);

void Radare_plugin_bin_free(RBinPlugin *bp);

PyObject *Radare_plugin_bin(Radare* self, PyObject *args);

#endif /* _PY_BIN_H */