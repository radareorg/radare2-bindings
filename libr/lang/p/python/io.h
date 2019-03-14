/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka, aronsky */

#ifndef _PY_IO_H
#define _PY_IO_H

#include <r_io.h>
#include "common.h"

void Radare_plugin_io_free(RIOPlugin *ap);

PyObject *Radare_plugin_io(Radare* self, PyObject *args);

#endif /* _PY_IO_H */