/* radare - LGPL - Copyright 2017 - xvilka */

// Exporting the R_ANAL_* enum constants

static void py_export_anal_enum(PyObject *tp_dict) {
#define PYENUM(name) PyDict_SetItemString(tp_dict, #name, PyLong_FromLong(name))
	// R_ANAL_OP_FAMILY_*
	PYENUM(R_ANAL_OP_FAMILY_UNKNOWN);
	PYENUM(R_ANAL_OP_FAMILY_CPU);
	PYENUM(R_ANAL_OP_FAMILY_FPU);
	PYENUM(R_ANAL_OP_FAMILY_MMX);
	PYENUM(R_ANAL_OP_FAMILY_SSE);
	PYENUM(R_ANAL_OP_FAMILY_PRIV);
	PYENUM(R_ANAL_OP_FAMILY_CRYPTO);
	PYENUM(R_ANAL_OP_FAMILY_VIRT);
	PYENUM(R_ANAL_OP_FAMILY_IO);
	PYENUM(R_ANAL_OP_FAMILY_LAST);
	// R_ANAL_OP_TYPE_*
	PYENUM(R_ANAL_OP_TYPE_COND);
	PYENUM(R_ANAL_OP_TYPE_REP);
	PYENUM(R_ANAL_OP_TYPE_MEM);
	PYENUM(R_ANAL_OP_TYPE_REG);
	PYENUM(R_ANAL_OP_TYPE_IND);
	PYENUM(R_ANAL_OP_TYPE_NULL);
	PYENUM(R_ANAL_OP_TYPE_JMP);
	PYENUM(R_ANAL_OP_TYPE_UJMP);
	PYENUM(R_ANAL_OP_TYPE_RJMP);
	PYENUM(R_ANAL_OP_TYPE_IJMP);
	PYENUM(R_ANAL_OP_TYPE_IRJMP);
	PYENUM(R_ANAL_OP_TYPE_CJMP);
	PYENUM(R_ANAL_OP_TYPE_MJMP);
	PYENUM(R_ANAL_OP_TYPE_UCJMP);
	PYENUM(R_ANAL_OP_TYPE_CALL);
	PYENUM(R_ANAL_OP_TYPE_UCALL);
	PYENUM(R_ANAL_OP_TYPE_RCALL);
	PYENUM(R_ANAL_OP_TYPE_ICALL);
	PYENUM(R_ANAL_OP_TYPE_IRCALL);
	PYENUM(R_ANAL_OP_TYPE_CCALL);
	PYENUM(R_ANAL_OP_TYPE_UCCALL);
	PYENUM(R_ANAL_OP_TYPE_RET);
	PYENUM(R_ANAL_OP_TYPE_CRET);
	PYENUM(R_ANAL_OP_TYPE_ILL);
	PYENUM(R_ANAL_OP_TYPE_UNK);
	PYENUM(R_ANAL_OP_TYPE_NOP);
	PYENUM(R_ANAL_OP_TYPE_MOV);
	PYENUM(R_ANAL_OP_TYPE_CMOV);
	PYENUM(R_ANAL_OP_TYPE_TRAP);
	PYENUM(R_ANAL_OP_TYPE_SWI);
	PYENUM(R_ANAL_OP_TYPE_UPUSH);
	PYENUM(R_ANAL_OP_TYPE_PUSH);
	PYENUM(R_ANAL_OP_TYPE_POP);
	PYENUM(R_ANAL_OP_TYPE_CMP);
	PYENUM(R_ANAL_OP_TYPE_ACMP);
	PYENUM(R_ANAL_OP_TYPE_ADD);
	PYENUM(R_ANAL_OP_TYPE_SUB);
	PYENUM(R_ANAL_OP_TYPE_IO);
	PYENUM(R_ANAL_OP_TYPE_MUL);
	PYENUM(R_ANAL_OP_TYPE_DIV);
	PYENUM(R_ANAL_OP_TYPE_SHR);
	PYENUM(R_ANAL_OP_TYPE_SHL);
	PYENUM(R_ANAL_OP_TYPE_SAL);
	PYENUM(R_ANAL_OP_TYPE_SAR);
	PYENUM(R_ANAL_OP_TYPE_OR);
	PYENUM(R_ANAL_OP_TYPE_AND);
	PYENUM(R_ANAL_OP_TYPE_XOR);
	PYENUM(R_ANAL_OP_TYPE_NOR);
	PYENUM(R_ANAL_OP_TYPE_NOT);
	PYENUM(R_ANAL_OP_TYPE_STORE);
	PYENUM(R_ANAL_OP_TYPE_LOAD);
	PYENUM(R_ANAL_OP_TYPE_LEA);
	PYENUM(R_ANAL_OP_TYPE_LEAVE);
	PYENUM(R_ANAL_OP_TYPE_ROR);
	PYENUM(R_ANAL_OP_TYPE_ROL);
	PYENUM(R_ANAL_OP_TYPE_XCHG);
	PYENUM(R_ANAL_OP_TYPE_MOD);
	PYENUM(R_ANAL_OP_TYPE_SWITCH);
	PYENUM(R_ANAL_OP_TYPE_CASE);
	PYENUM(R_ANAL_OP_TYPE_LENGTH);
	PYENUM(R_ANAL_OP_TYPE_CAST);
	PYENUM(R_ANAL_OP_TYPE_NEW);
	PYENUM(R_ANAL_OP_TYPE_ABS);
	PYENUM(R_ANAL_OP_TYPE_CPL);
	PYENUM(R_ANAL_OP_TYPE_CRYPTO);
	PYENUM(R_ANAL_OP_TYPE_SYNC);
	// R_ANAL_STACK
	PYENUM(R_ANAL_STACK_NULL);
	PYENUM(R_ANAL_STACK_NOP);
	PYENUM(R_ANAL_STACK_INC);
	PYENUM(R_ANAL_STACK_GET);
	PYENUM(R_ANAL_STACK_SET);
	PYENUM(R_ANAL_STACK_RESET);
	PYENUM(R_ANAL_STACK_ALIGN);
#undef E
}

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
		PyObject *arglist = Py_BuildValue ("(i, "BYTES_FMT")", addr, buf, len);
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
			op->fail = getI (dict, "fail");
			op->stackop = getI (dict, "stackop");
			op->stackptr = getI (dict, "stackptr");
			op->ptr = getI (dict, "ptr");
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
