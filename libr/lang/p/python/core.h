#ifndef _PY_CORE_H
#define _PY_CORE_H

#include <r_core.h>
#include "common.h"

extern RCore *core;

void Radare_plugin_core_free(RCorePlugin *ap);

PyObject *Radare_plugin_core(Radare* self, PyObject *args);

#endif /* _PY_CORE_H */