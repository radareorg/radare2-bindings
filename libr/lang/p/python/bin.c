/* radare - LGPL - Copyright 2017-2019 - xvilka, pancake */

#include "bin.h"
#include "core.h"

/* The structure, representing simplified version of RBinFile/RBinObject */
typedef struct {
	PyObject_HEAD
	PyObject *bin_obj; /* RBinFile->o->bin_obj */
	PyObject *buf;  /* RBinFile->buf */
	ut64 size; /* RBinFile->size */
	ut64 loadaddr; /* RBinFile->o->loadaddr */
} PyBinFile;

static void PyBinFile_dealloc(PyBinFile* self) {
	Py_XDECREF (self->bin_obj);
	Py_XDECREF (self->buf);
	Py_TYPE (self)->tp_free((PyObject*)self);
}

static PyObject * PyBinFile_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	PyBinFile *self = (PyBinFile *)type->tp_alloc (type, 0);
	if (self) {
		// Create empty buffers
		self->bin_obj = PyUnicode_FromString ("");
		if (!self->bin_obj) {
			Py_DECREF (self);
			return NULL;
		}
		self->buf = PyUnicode_FromString ("");
		if (!self->buf) {
			Py_DECREF (self);
			return NULL;
		}
		self->size = 0;
		self->loadaddr = 0;
	}
	return (PyObject *)self;
}

static int PyBinFile_init(PyBinFile *self, PyObject *args, PyObject *kwds) {
	static char *kwlist[] = {
		"bin_obj",
		"buf",
		"size",
		"loadaddr",
		NULL
	};
	PyObject *bin_obj = NULL, *buf = NULL;
	self->size = 0;
	self->loadaddr = 0;
	if (!PyArg_ParseTupleAndKeywords (args, kwds, "|OOKK",
			(char **)kwlist, &bin_obj, &buf, &self->size, &self->loadaddr)) {
		return -1;
	}
	self->bin_obj = bin_obj;
	self->buf = buf;
	return 0;
}

// write_bytes(addr, bytes)
// TODO: Return an error
static PyObject *RBin_write_bytes(Radare* self, PyObject *args) {
	char *buf = NULL;
	ut64 addr = 0;
	int buf_sz = 0;
	if (!PyArg_ParseTuple (args, "(K,y#iK)", &addr, &buf, &buf_sz)) {
		return NULL;
	}
	return PyUnicode_FromString ("");
}

static PyMemberDef PyBinFile_members[] = {
	{"bin_obj", T_OBJECT_EX, offsetof(PyBinFile, bin_obj), 0, "bin_obj"},
	{"buf", T_OBJECT_EX, offsetof(PyBinFile, buf), 0, "buf"},
	{"size", T_INT, offsetof(PyBinFile, size), 0, "size"},
	{"loadaddr", T_INT, offsetof(PyBinFile, loadaddr), 0, "loadaddr"},
	{NULL}  /* Sentinel */
};

static PyMethodDef PyBinFile_methods[] = {
	{"write_bytes", (PyCFunction)RBin_write_bytes, METH_VARARGS,
		"Write bytes back into RBin buffer" },
	{NULL}  /* Sentinel */
};

PyTypeObject PyBinFileType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"binfile.BinFile",         /*tp_name*/
	sizeof (PyBinFile),        /*tp_basicsize*/
	0,                         /*tp_itemsize*/
	(destructor)PyBinFile_dealloc,/*tp_dealloc*/
	0,                         /*tp_print*/
	0,                         /*tp_getattr*/
	0,                         /*tp_setattr*/
	0,                         /*tp_compare*/
	0,                         /*tp_repr*/
	0,                         /*tp_as_number*/
	0,                         /*tp_as_sequence*/
	0,                         /*tp_as_mapping*/
	0,                         /*tp_hash */
	0,                         /*tp_call*/
	0,                         /*tp_str*/
	0,                         /*tp_getattro*/
	0,                         /*tp_setattro*/
	0,                         /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	"BinFile objects",          /* tp_doc */
	0,                         /* tp_traverse */
	0,                         /* tp_clear */
	0,                         /* tp_richcompare */
	0,                         /* tp_weaklistoffset */
	0,                         /* tp_iter */
	0,                         /* tp_iternext */
	PyBinFile_methods,         /* tp_methods */
	PyBinFile_members,         /* tp_members */
	0,                         /* tp_getset */
	0,                         /* tp_base */
	0,                         /* tp_dict */
	0,                         /* tp_descr_get */
	0,                         /* tp_descr_set */
	0,                         /* tp_dictoffset */
	(initproc)PyBinFile_init,  /* tp_init */
	0,                         /* tp_alloc */
	PyBinFile_new,             /* tp_new */
};

static PyModuleDef PyBinModule = {
	PyModuleDef_HEAD_INIT,
	"binfile",
	NULL, -1, PyBinFile_methods,
	NULL, NULL, NULL, NULL
};

PyObject *init_pybinfile_module(void) {
	if (PyType_Ready (&PyBinFileType) < 0) {
		return NULL;
	}
	PyObject *m = PyModule_Create (&PyBinModule);
	if (!m) {
		eprintf ("Cannot create python3 RBinFile module\n");
		return NULL;
	}
	return m;
}

PyObject* create_PyBinFile(RBinFile *binfile)
{
	if (!binfile) return NULL;
	PyObject *pb = _PyObject_New(&PyBinFileType);
	if (!pb) {
		PyErr_Print();
		return NULL;
	}
	pb = PyObject_Init(pb, &PyBinFileType);
	if (!pb) {
		PyErr_Print();
		return NULL;
	}
	if (binfile->o) {
		((PyBinFile*)pb)->bin_obj = binfile->o->bin_obj;
		((PyBinFile*)pb)->loadaddr = binfile->o->loadaddr;
	}
	ut64 buf_size;
	const ut8 *buf_ptr = r_buf_data (binfile->buf, &buf_size);
	if (binfile->buf) {
		Py_buffer pybuf = {
			.buf = (void*) buf_ptr,
			.len = buf_size,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1
		};
		((PyBinFile*)pb)->buf = PyMemoryView_FromBuffer (&pybuf);
	}
	((PyBinFile*)pb)->size = binfile->size;
	return pb;
}
/* Plugin callbacks */

// dict -> RBinSection
// "name" : name,
// "size" : size,
// "vsize" : vsize,
// "vaddr" : vaddr,
// "paddr" : paddr,
// "arch" : arch,
// "format" : format,
// "bits" : bits,
// "has_strings" : bool,
// "add" : bool,
// "is_data" : bool
#define READ_SECTION(sec, pysec) \
		sec->name = getS (pysec, "name"); \
		sec->size = getI (pysec, "size"); \
		sec->vsize = getI (pysec, "vsize"); \
		sec->vaddr = getI (pysec, "vaddr"); \
		sec->paddr = getI (pysec, "paddr"); \
		sec->perm = getI (pysec, "perm"); \
		sec->arch = getS (pysec, "arch"); \
		sec->format = getS (pysec, "format"); \
		sec->bits = getI (pysec, "bits"); \
		sec->has_strings = getI (pysec, "has_strings"); \
		sec->add = getI (pysec, "add"); \
		sec->is_data = getI (pysec, "is_data")

// dict -> RBinSymbol
// "name" : name,
// "dname" : dname,
// "classname" : classname,
// "forwarder" : forwarder
// "bind" : bind,
// "type" : type,
// "visibility_str" : visibility_str,
// "vaddr" : vaddr,
// "paddr" : paddr,
// "size" : size,
// "ordinal" : ordinal,
// "visibility" : visibility,
// "bits" : bits,
// "method_flags" : method_flags,
// "dup_count" : dup_count
#define READ_SYMBOL(sym, pysym) \
		sym->name = getS (pysym, "name"); \
		sym->dname = getS (pysym, "dname"); \
		sym->classname = getS (pysym, "classname"); \
		sym->forwarder = getS (pysym, "forwarder"); \
		sym->bind = getS (pysym, "bind"); \
		sym->type = getS (pysym, "type"); \
		sym->visibility_str = getS (pysym, "visibility_str"); \
		sym->vaddr = getI (pysym, "vaddr"); \
		sym->paddr = getI (pysym, "paddr"); \
		sym->size = getI (pysym, "size"); \
		sym->ordinal = getI (pysym, "ordinal"); \
		sym->visibility = getI (pysym, "visibility"); \
		sym->bits = getI (pysym, "bits"); \
		sym->method_flags = getI (pysym, "method_flags"); \
		sym->dup_count = getI (pysym, "dup_count")

// dict -> RBinImport
// "name" : name,
// "bind" : bind,
// "type" : type,
// "classname" : classname,
// "descriptor" : descriptor,
// "ordinal" : ordinal,
// "visibility" : visibility,
#define READ_IMPORT(imp, pyimp) \
		imp->name = getS (pyimp, "name"); \
		imp->bind = getS (pyimp, "bind"); \
		imp->type = getS (pyimp, "type"); \
		imp->classname = getS (pyimp, "classname"); \
		imp->descriptor = getS (pyimp, "descriptor"); \
		imp->ordinal = getI (pyimp, "ordinal"); \
		imp->visibility = getI (pyimp, "visibility")

// dict -> RBinSection
// "type" : type, (integer)
// "additive" : additive, (integer)
// "symbol" : RBinSymbol,
// "import" : RBinImport,
// "addend" : addend,
// "vaddr" : vaddr,
// "paddr" : paddr,
// "visibility" : visibility,
// "is_ifunc" : bool
#define READ_RELOC(rel, pyrel) \
		rel->type = getI (pyrel, "type"); \
		rel->additive = getI (pyrel, "additive"); \
		PyObject *pysym = getO (pyrel, "symbol"); \
		if (pysym) { READ_SYMBOL (rel->symbol, pysym); } \
		else { rel->symbol = NULL; } \
		PyObject *pyimp = getO (pyrel, "import"); \
		if (pyimp) { READ_IMPORT (rel->import, pyimp); } \
		else { rel->import = NULL; } \
		rel->addend = getI (pyrel, "addend"); \
		rel->vaddr = getI (pyrel, "vaddr"); \
		rel->paddr = getI (pyrel, "paddr"); \
		rel->visibility = (int) getI (pyrel, "visibility"); \
		rel->is_ifunc = getI (pysym, "is_ifunc")

static void *py_load_buffer_cb = NULL;
static void *py_check_buffer_cb = NULL;
static void *py_destroy_cb = NULL;
static void *py_baddr_cb = NULL;
static void *py_sections_cb = NULL;
static void *py_imports_cb = NULL;
static void *py_symbols_cb = NULL;
static void *py_relocs_cb = NULL;
static void *py_binsym_cb = NULL;
static void *py_entries_cb = NULL;
static void *py_info_cb = NULL;

static bool py_load_buffer(RBinFile *arch, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	int rres = 0;
	ut64 size = 0;
	const ut8 *buf_data = r_buf_data (buf, &size);

	if (!arch) return false;
	if (py_load_buffer_cb) {
		PyObject *pybinfile = create_PyBinFile(arch);
		if (!pybinfile) return false;
		Py_buffer pybuf = {
			.buf = (void*) buf_data,
			.len = size,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1,
		};
		PyObject *memview = PyMemoryView_FromBuffer (&pybuf);
		PyObject *arglist = Py_BuildValue ("(O,N,K)", pybinfile, memview, loadaddr);
		if (!arglist) {
			PyErr_Print();
			return false;
		}
		PyObject *result = PyEval_CallObject (py_load_buffer_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *res = PyList_GetItem (result, 0);
			rres = PyNumber_AsSsize_t (res, NULL);
			if (rres) return true;
		} else {
			eprintf ("Unknown type returned. List was expected.\n");
		}
	}
	return false;
}

static bool py_check_buffer(RBuffer *buf)
{
	int rres = 0;
	ut64 length = 0;
	const ut8 *buf_data = r_buf_data (buf, &length);


	if (!buf_data || length == 0) {
		eprintf("Empty buffer!\n");
	}
	if (py_check_buffer_cb) {
		if (!PyCallable_Check(py_check_buffer_cb)) {
			PyErr_SetString(PyExc_TypeError, "parameter must be callable");
			return false;
		}
		// check_buffer(buf) - returns true/false
		Py_buffer pybuf = {
			.buf = (void *) buf_data, // Warning: const is lost when casting
			.len = length,
			.readonly = 1,
			.ndim = 1,
			.itemsize = 1,
		};
		PyObject *memview = PyMemoryView_FromBuffer (&pybuf);
		PyObject *arglist = Py_BuildValue ("(N)", memview);
		if (!arglist) {
			PyErr_Print();
			return false;
		}
		PyObject *result = PyEval_CallObject (py_check_buffer_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *res = PyList_GetItem (result, 0);
			rres = PyNumber_AsSsize_t (res, NULL);
			if (rres) {
				return true;
			}
		} else {
			eprintf ("check_bytes: Unknown type returned. List was expected.\n");
		}
	}
	return false;

}

static void py_destroy(RBinFile *arch) {
	if (!arch) return;
	if (py_destroy_cb) {
		// destroy(RBinFile) - returns something
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return;
		}
		PyObject *result = PyEval_CallObject (py_destroy_cb, arglist);
		if (!(result && PyList_Check (result))) {
			eprintf ("destroy: Unknown type returned. List was expected.\n");
		}
	}
}

static ut64 py_baddr(RBinFile *arch) {
	ut64 rres = 0;

	if (!arch) return 0;
	if (py_baddr_cb) {
		// baddr(RBinFile) - returns baddr
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return 0;
		}
		PyObject *result = PyEval_CallObject (py_baddr_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *res = PyList_GetItem (result, 0);
			rres = PyLong_AsLong (res);
			if (rres) return rres;
		} else {
			PyErr_Print();
			eprintf ("baddr: Unknown type returned. List was expected.\n");
		}
	}
	return 0;
}

static RBinAddr* py_binsym(RBinFile *arch, int sym) {
	RBinAddr* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = R_NEW0 (RBinAddr))) {
		return NULL;
	}
	if (py_binsym_cb) {
		// binsym(RBinFile, symtype) - returns RBinAddr if found
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O, i)", pybinfile, sym);
		if (!arglist) {
			PyErr_Print();
			return NULL;
		}
		PyObject *result = PyEval_CallObject (py_binsym_cb, arglist);
		if (result && PyList_Check (result)) {
			// dict -> RBinEntry
			// "vaddr" : vaddr,
			// "paddr" : paddr,
			// "hpaddr" : hpaddr,
			// "type" : type,
			// "bits" : bits
			PyObject *pybinsym = PyList_GetItem (result, 0);
			ret->vaddr = getI (pybinsym, "vaddr");
			ret->paddr = getI (pybinsym, "paddr");
			ret->hpaddr = getI (pybinsym, "hpaddr");
			ret->type = getI (pybinsym, "type");
			ret->bits = getI (pybinsym, "bits");
		} else {
			eprintf ("binsym: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RList* py_entries(RBinFile *arch) {
	ssize_t listsz = 0;
	ssize_t i = 0;
	RList* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = r_list_new())) {
		return NULL;
	}
	if (py_entries_cb) {
		// entries(RBinFile) - returns list of entries
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return NULL;
		}
		PyObject *result = PyEval_CallObject (py_entries_cb, arglist);
		if (result && PyList_Check (result)) {
			listsz = PyList_Size(result);
			for (i = 0; i < listsz; i++) {
				// dict -> RBinEntry
				// "vaddr" : vaddr,
				// "paddr" : paddr,
				// "hpaddr" : hpaddr,
				// "type" : type,
				// "bits" : bits
				PyObject *pyentry = PyList_GetItem (result, i);
				RBinAddr *entry = R_NEW0 (RBinAddr);
				if (!entry) continue;
				entry->vaddr = getI (pyentry, "vaddr");
				entry->paddr = getI (pyentry, "paddr");
				entry->hpaddr = getI (pyentry, "hpaddr");
				entry->type = getI (pyentry, "type");
				entry->bits = getI (pyentry, "bits");
				r_list_append(ret, entry);
			}
		} else {
			eprintf ("entries: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RList* py_sections(RBinFile *arch) {
	ssize_t listsz = 0;
	ssize_t i = 0;
	RList* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = r_list_new())) {
		return NULL;
	}
	if (py_sections_cb) {
		// sections(RBinFile) - returns list of sections
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return NULL;
		}
		PyObject *result = PyEval_CallObject (py_sections_cb, arglist);
		if (result && PyList_Check (result)) {
			listsz = PyList_Size(result);
			for (i = 0; i < listsz; i++) {
				// dict -> RBinSection
				PyObject *pysection = PyList_GetItem (result, i);
				RBinSection *section = R_NEW0(RBinSection);
				if (!section) continue;
				READ_SECTION(section, pysection);
				r_list_append(ret, section);
			}
		} else {
			eprintf ("sections: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RList* py_imports(RBinFile *arch) {
	ssize_t listsz = 0;
	ssize_t i = 0;
	RList* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = r_list_new())) {
		return NULL;
	}
	if (py_imports_cb) {
		// imports(RBinFile) - returns list of imports
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return NULL;
		}
		PyObject *result = PyEval_CallObject (py_imports_cb, arglist);
		if (result && PyList_Check (result)) {
			listsz = PyList_Size(result);
			for (i = 0; i < listsz; i++) {
				// dict -> RBinSection
				PyObject *pyimport = PyList_GetItem (result, i);
				RBinImport *import = R_NEW0 (RBinImport);
				if (!import) continue;
				READ_IMPORT(import, pyimport);
				r_list_append(ret, import);
			}
		} else {
			eprintf ("imports: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RList* py_symbols(RBinFile *arch) {
	ssize_t listsz = 0;
	ssize_t i = 0;
	RList* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = r_list_new())) {
		return NULL;
	}
	if (py_symbols_cb) {
		// symbols(RBinFile) - returns list of symbols
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return 0;
		}
		PyObject *result = PyEval_CallObject (py_symbols_cb, arglist);
		if (result && PyList_Check (result)) {
			listsz = PyList_Size(result);
			for (i = 0; i < listsz; i++) {
				// dict -> RBinSection
				PyObject *pysym = PyList_GetItem (result, i);
				RBinSymbol *symbol = R_NEW0 (RBinSymbol);
				if (!symbol) continue;
				READ_SYMBOL(symbol, pysym);
				r_list_append(ret, symbol);
			}
		} else {
			eprintf ("symbols: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RList* py_relocs(RBinFile *arch) {
	ssize_t listsz = 0;
	ssize_t i = 0;
	RList* ret = NULL;

	if (!arch) return NULL;
	if (!(ret = r_list_new())) {
		return NULL;
	}
	if (py_relocs_cb) {
		// relocs(RBinFile) - returns list of relocations
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return 0;
		}
		PyObject *result = PyEval_CallObject (py_relocs_cb, arglist);
		if (result && PyList_Check (result)) {
			listsz = PyList_Size(result);
			for (i = 0; i < listsz; i++) {
				// dict -> RBinSection
				PyObject *pyrel = PyList_GetItem (result, i);
				RBinReloc *reloc = R_NEW0 (RBinReloc);
				if (!reloc) continue;
				READ_RELOC(reloc, pyrel);
				r_list_append(ret, reloc);
			}
		} else {
			eprintf ("relocs: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

static RBinInfo *py_info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	if (!arch) return NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	if (py_info_cb) {
		// info(RBinFile) - returns dictionary (structure) for RAnalOp
		PyObject *pybinfile = create_PyBinFile(arch);
		PyObject *arglist = Py_BuildValue ("(O)", pybinfile);
		if (!arglist) {
			PyErr_Print();
			return NULL;
		}
		PyObject *result = PyEval_CallObject (py_info_cb, arglist);
		if (result && PyList_Check (result)) {
			PyObject *dict = PyList_GetItem (result, 0);
			/* TODO: Check for empty values first! */
			ret->lang = NULL;
			ret->file = arch->file? strdup (arch->file): NULL;
			ret->type = getS (dict, "type");
			ret->bclass = getS (dict, "bclass");
			ret->rclass = getS (dict, "rclass");
			ret->os = getS (dict, "os");
			ret->subsystem = getS (dict, "subsystem");
			ret->machine = getS (dict, "machine");
			ret->arch = getS (dict, "arch");
			ret->has_va = getB (dict, "has_va");
			ret->bits = (int) getI (dict, "bits");
			ret->big_endian = (int) getI (dict, "big_endian");
			ret->dbg_info = getI (dict, "dbg_info");
		} else {
			eprintf ("info: Unknown type returned. List was expected.\n");
		}
	}
	return ret;
}

void Radare_plugin_bin_free(RBinPlugin *bp) {
	free ((char *)bp->name);
	free ((char *)bp->desc);
	free ((char *)bp->license);
	free (bp);
}

/* TODO: Add missing exported symbols */
/* TODO: Fold the repeating code - may be add some macro? */
PyObject *Radare_plugin_bin(Radare* self, PyObject *args) {
	void *ptr = NULL;
	init_pybinfile_module ();
	PyObject *arglist = Py_BuildValue("(i)", 0);
	PyObject *o = PyEval_CallObject (args, arglist);

	RBinPlugin *bp = R_NEW0 (RBinPlugin);
	bp->name = getS (o,"name");
	bp->desc = getS (o, "desc");
	bp->license = getS (o, "license");
	ptr = getF (o, "load");
	if (ptr) {
		eprintf ("warning: Plugin %s must implement load_buffer method instead of load.\n", bp->name);
	}
	ptr = getF (o, "load_buffer");
	if (getF (o, "load_bytes")) {
		eprintf ("warning: Plugin %s should implement load_buffer method instead of load_bytes.\n", bp->name);
		if (!ptr) {
			// fallback
			ptr = getF (o, "load_bytes");
		}
	}
	if (ptr) {
		Py_INCREF (ptr);
		py_load_buffer_cb = ptr;
		bp->load_buffer = py_load_buffer;
	}
	ptr = getF (o, "destroy");
	if (ptr) {
		Py_INCREF (ptr);
		py_destroy_cb = ptr;
		bp->destroy = py_destroy;
	}
	ptr = getF (o, "check_buffer");
	if (getF (o, "check_bytes")) {
		eprintf ("warning: Plugin %s should implement check_buffer method instead of check_bytes.\n", bp->name);
		if (!ptr) {
			// fallback
			ptr = getF (o, "check_bytes");
		}
	}
	if (ptr) {
		Py_INCREF (ptr);
		py_check_buffer_cb = ptr;
		bp->check_buffer = py_check_buffer;
	}
	ptr = getF (o, "baddr");
	if (ptr) {
		Py_INCREF (ptr);
		py_baddr_cb = ptr;
		bp->baddr = py_baddr;
	}
	// Get RList* here
	ptr = getF (o, "entries");
	if (ptr) {
		Py_INCREF (ptr);
		py_entries_cb = ptr;
		bp->entries = py_entries;
	}
	// Get RList* here
	ptr = getF (o, "sections");
	if (ptr) {
		Py_INCREF (ptr);
		py_sections_cb = ptr;
		bp->sections = py_sections;
	}
	// Get RList* here
	ptr = getF (o, "imports");
	if (ptr) {
		Py_INCREF (ptr);
		py_imports_cb = ptr;
		bp->imports = py_imports;
	}
	// Get RList* here
	ptr = getF (o, "symbols");
	if (ptr) {
		Py_INCREF (ptr);
		py_symbols_cb = ptr;
		bp->symbols = py_symbols;
	}
	// Get RList* here
	ptr = getF (o, "relocs");
	if (ptr) {
		Py_INCREF (ptr);
		py_relocs_cb = ptr;
		bp->relocs = py_relocs;
	}
	// Get RBinAddr* here
	ptr = getF (o, "binsym");
	if (ptr) {
		Py_INCREF (ptr);
		py_binsym_cb = ptr;
		bp->binsym = py_binsym;
	}
	ptr = getF (o, "info");
	if (ptr) {
		Py_INCREF (ptr);
		py_info_cb = ptr;
		bp->info = py_info;
	}
	Py_DECREF (o);

	RLibStruct lp = {};
	lp.type = R_LIB_TYPE_BIN;
	lp.data = bp;
	lp.free = (void (*)(void *data))Radare_plugin_bin_free;
	r_lib_open_ptr (core->lib, "python.py", NULL, &lp);
	Py_RETURN_TRUE;
}
