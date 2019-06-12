/* radare - LGPL - Copyright 2017-2019 - pancake, xvilka */

// Exporting the R_ANAL_* enum constants
#include <r_reg.h>
#include "anal.h"
#include "core.h"

void py_export_anal_enum(PyObject *tp_dict) {

#define PYENUM(name) {\
		PyObject *o = PyLong_FromLong(name); \
		if (o) { \
			PyDict_SetItemString(tp_dict, #name, o); \
			Py_DECREF(o); \
		}\
	}

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

#define READ_REG(dict, reg) \
	if (dict && PyDict_Check(dict)) { \
		reg->name = getS (dict, "name"); \
		reg->type = getI (dict, "type"); \
		reg->size = getI (dict, "size"); \
		reg->offset = getI (dict, "offset"); \
		reg->packed_size = getI (dict, "packed_size"); \
		reg->is_float = getB (dict, "is_float"); \
		reg->flags = getS (dict, "flags"); \
		reg->index = getI (dict, "index"); \
		reg->arena = getI (dict, "arena"); \
	}

#define READ_VAL(dict, val, tmpreg) \
	if (dict && PyDict_Check(dict)) { \
		val->absolute = getI (dict, "absolute"); \
		val->memref = getI (dict, "memref"); \
		val->base = getI (dict, "base"); \
		val->delta = getI (dict, "delta"); \
		val->imm = getI (dict, "imm"); \
		val->mul = getI (dict, "mul"); \
		val->sel = getI (dict, "sel"); \
		tmpreg = getO (dict, "reg"); \
		READ_REG(tmpreg, val->reg) \
		tmpreg = getO (dict, "regdelta"); \
		READ_REG(tmpreg, val->regdelta) \
	}

static void *py_set_reg_profile_cb = NULL;
static void *py_anal_cb = NULL;
static void *py_archinfo_cb = NULL;

static int py_set_reg_profile(RAnal *a) {
	const char *profstr = "";
	if (py_set_reg_profile_cb) {
		PyObject *result = PyObject_CallObject (py_set_reg_profile_cb, NULL);
		if (result) {
			profstr = PyUnicode_AsUTF8 (result);
			return r_reg_set_profile_string (a->reg, profstr);
		} else {
			eprintf ("Unknown type returned. String was expected.\n");
			PyErr_Print();
		}
	}
	return -1;
}

static int py_anal(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	PyObject *tmpreg = NULL;
	int size = 0;
	int seize = -1;
	int i = 0;
	if (!op) return -1;
	if (py_anal_cb) {
		memset(op, 0, sizeof (RAnalOp));
		// anal(addr, buf) - returns size + dictionary (structure) for RAnalOp
		Py_buffer pybuf = {
			.buf = (void *) buf, // Warning: const is lost when casting
			.len = len,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1,
		};
		PyObject *memview = PyMemoryView_FromBuffer (&pybuf);
		PyObject *arglist = Py_BuildValue ("(NK)", memview, addr);
		PyObject *result = PyEval_CallObject (py_anal_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *len = PyList_GetItem (result, 0);
			PyObject *dict = PyList_GetItem (result, 1);
			if (dict && PyDict_Check (dict)) {
				seize = PyNumber_AsSsize_t (len, NULL);
				op->type = getI (dict, "type");
				op->cycles = getI (dict, "cycles");
				op->size = seize;
				op->addr = getI (dict, "addr");
				op->delay = getI (dict, "delay");
				op->jump = getI (dict, "jump");
				op->fail = getI (dict, "fail");
				op->stackop = getI (dict, "stackop");
				op->stackptr = getI (dict, "stackptr");
				op->ptr = getI (dict, "ptr");
				op->eob = getB (dict, "eob");
				// Loading 'src' and 'dst' values
				// SRC is is a list of 3 elements
				PyObject *tmpsrc = getO (dict, "src");
				if (tmpsrc && PyList_Check (tmpsrc)) {
					for (i = 0; i < 3; i++) {
						PyObject *tmplst = PyList_GetItem (tmpsrc, i);
						// Read value and underlying regs
						READ_VAL(tmplst, op->src[i], tmpreg)
					}
				}
				PyObject *tmpdst = getO (dict, "dst");
				// Read value and underlying regs
				READ_VAL(tmpdst, op->dst, tmpreg)
				// Loading 'var' value if presented
				r_strbuf_set (&op->esil, getS (dict, "esil"));
				// TODO: Add opex support here
				Py_DECREF (dict);
			}
			Py_DECREF (result);
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
			PyErr_Print();
		}
	}
	op->size = size = seize;
	return seize;
}

static int py_archinfo(RAnal *a, int query) {
	if (py_archinfo_cb) {
		PyObject *arglist = Py_BuildValue ("(i)", query);
		PyObject *result = PyEval_CallObject (py_archinfo_cb, arglist);
		if (result) {
			return PyLong_AsLong (result); /* Python only returns long... */
		}
		eprintf ("Unknown type returned. Int was expected.\n");
	}
	return -1;
}

void Radare_plugin_anal_free(RAnalPlugin *ap) {
	free ((char *)ap->name);
	free ((char *)ap->arch);
	free ((char *)ap->license);
	free ((char *)ap->desc);
	free (ap);
}

PyObject *Radare_plugin_anal(Radare* self, PyObject *args) {
	void *ptr = NULL;
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyObject_CallObject (args, arglist);

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
	ptr = getF (o, "archinfo");
	if (ptr) {
		Py_INCREF (ptr);
		py_archinfo_cb = ptr;
		ap->archinfo = py_archinfo;
	}
	Py_DECREF (o);

	RLibStruct lp = {};
	lp.type = R_LIB_TYPE_ANAL;
	lp.data = ap;
	lp.free = (void (*)(void *data))Radare_plugin_anal_free;
	r_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
