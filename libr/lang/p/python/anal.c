/* radare - LGPL - Copyright 2017 - xvilka */

static void *py_set_reg_profile_cb = NULL;
static void *py_anal_cb = NULL;

static int py_set_reg_profile(RAnal *a) {
	int res = -1;
	const char *profstr = "";
	if (py_set_reg_profile_cb) {
		PyObject *result = PyEval_CallObject (py_set_reg_profile_cb, NULL);
		if (result) {
			profstr = PySTRING_ASSTRING (result);
			res = r_reg_set_profile_string (a->reg, profstr);
		} else {
			eprintf ("Unknown type returned. String was expected.\n");
		}
	}
	return res;
}

static int py_anal(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int size = 0;
	int seize = -1;
	if (!op) return -1;
	if (py_anal_cb) {
		memset(op, 0, sizeof (RAnalOp));
		// anal(addr, buf) - returns size + dictionary (structure) for RAnalOp
		PyObject *arglist = Py_BuildValue ("(i, s#)", addr, buf, len);
		PyObject *result = PyEval_CallObject (py_anal_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *len = PyList_GetItem (result, 0);
			PyObject *dict = PyList_GetItem (result, 1);
			seize = PyNumber_AsSsize_t (len, NULL);
			op->type = getI (dict, "type");
			op->cycles = getI (dict, "cycles");
			op->size = seize;
			op->addr = getI (dict, "addr");
			op->jump = getI (dict, "jump");
			op->stackop = getI (dict, "stackop");
			op->stackptr = getI (dict, "stackptr");
			op->eob = getI (dict, "eob");
			r_strbuf_set (&op->esil, getS (dict, "esil"));
			// TODO: Add opex support here
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
		}
	}
	op->size = size = seize;
	return seize;
}

static PyObject *Radare_plugin_anal(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RAnalPlugin *ap = R_NEW0 (RAnalPlugin);
	ap->name = getS (o,"name");
	ap->arch = getS (o, "arch");
	ap->license = getS (o, "license");
	ap->desc = getS (o, "desc");
	ap->bits = getI (o, "bits");
	ap->esil = getI (o, "esil");
	ptr = getF (o, "op");
	if (ptr) {
		Py_INCREF (ptr);
		py_anal_cb = ptr;
		ap->op = py_anal;
	}
	ptr = getF (o, "set_reg_profile");
	if (ptr) {
		Py_INCREF (ptr);
		py_set_reg_profile_cb = ptr;
		ap->set_reg_profile = py_set_reg_profile;
	}

	RLibStruct *lp = R_NEW0 (RLibStruct);
	lp->type = R_LIB_TYPE_ANAL;
	lp->data = ap;
	r_lib_open_ptr (core->lib, "python.py", NULL, lp);
	return Py_True;
}
