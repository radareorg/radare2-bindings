/* radare - LGPL - Copyright 2009-2016 - pancake */

/* TODO : move into a struct stored in the plugin struct */
static void *py_assemble_cb = NULL;
static void *py_disassemble_cb = NULL;

static int py_assemble(RAsm *a, RAsmOp *op, const char *str) {
	int i, size = 0;
	int seize = -1;
	const char *opstr = str;
	if (py_assemble_cb) {
		PyObject *arglist = Py_BuildValue ("(z)", str);
		PyObject *result = PyEval_CallObject (py_assemble_cb, arglist);
		if (result && PyList_Check (result)) {
			seize = size = PyList_Size (result);
			for (i = 0; i < size ; i++) {
				PyObject *len = PyList_GetItem (result, i);
				op->buf[i] = PyNumber_AsSsize_t (len, NULL);
			}
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
		}
	}
	op->size = size = seize;
	strncpy (op->buf_asm, opstr, sizeof (op->buf_asm));
	r_hex_bin2str (op->buf, op->size, op->buf_hex);
	return seize;
}

static int py_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int size = 0;
	int seize = -1;
	const char *opstr = "invalid";
	if (py_disassemble_cb) {
		PyObject *arglist = Py_BuildValue ("("BYTES_FMT")", buf, len);
		PyObject *result = PyEval_CallObject (py_disassemble_cb, arglist);
		eprintf("obj: %s\n", PySTRING_ASSTRING(PyObject_Str(result)));
		if (result && PyList_Check (result)) {
			PyObject *len = PyList_GetItem (result, 0);
			PyObject *str = PyList_GetItem (result, 1);
			seize = PyNumber_AsSsize_t (len, NULL);
			opstr = PySTRING_ASSTRING (str);
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
		}
	}
	op->size = size = seize;
	strncpy (op->buf_asm, opstr, sizeof (op->buf_asm));
	r_hex_bin2str (buf, op->size, op->buf_hex);
	return seize;
}

static void Radare_plugin_asm_free(RAsmPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->arch);
	free ((char *)ap->license);
	free ((char *)ap->desc);
	free (ap);
}

static PyObject *Radare_plugin_asm(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RAsmPlugin *ap = R_NEW0 (RAsmPlugin);
	ap->name = getS (o,"name");
	ap->arch = getS (o, "arch");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ap->bits = getI (o, "bits");
	ptr = getF (o, "disassemble");
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
