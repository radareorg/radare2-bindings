/* radare - LGPL - Copyright 2014-2019 pancake */

#define _XOPEN_SOURCE 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>

#include "./duk/duktape.c"
#include "./duk/duk_console.c"

static char *mystrdup(const char *s) {
	char *p = NULL;
	if (s) {
		int len = strlen (s)+1;
		p = malloc (len);
		if (p) {
			memcpy (p, s, len);
		}
	}
	return p;
}

static int lang_duktape_file(RLang *lang, const char *file);

static int lang_duktape_init(void *user) {
	return true;
}

static int lang_duktape_fini(void *user) {
	return true;
}

static RCore *Gcore = NULL;
static duk_context *ctx;
static int is_init = 0;

static RAsmPlugin *asm_plugin = NULL;

static void pushBuffer(const ut8 *buf, int len) {
	int i;
	duk_push_fixed_buffer (ctx, len);
	for (i=0; i<len; i++) {
		duk_push_number (ctx, buf[i]);
		duk_put_prop_index (ctx, -2, i);
	}
	// buffer is in stack[-1]
}

static int duk_assemble(RAsm *a, RAsmOp *op, const char *str) {
	int i, res = 0;
	// call myasm function if available
	duk_push_global_stash (ctx);
	duk_dup (ctx, 0);  /* timer callback */
	duk_get_prop_string (ctx, -2, "asmfun");
	a->cur->user = duk_require_tval (ctx, -1);
	if (duk_is_callable (ctx, -1)) {
		duk_push_string (ctx, str);
		duk_call (ctx, 1);
		// [ array of bytes ]
		//duk_dup_top (ctx);
		res = duk_get_length (ctx, -1);
		op->size = res;
		ut8 *buf = calloc (res, 1);
		if (buf) {
			for (i = 0; i < res; i++) {
				duk_dup_top (ctx);
				duk_get_prop_index (ctx, -2, i);
				buf[i] = duk_to_int (ctx, -1);
			}
			r_asm_op_set_buf (op, buf, res);
			free (buf);
		}
	}
	if (res < 1) {
		res = -1;
	}
	return res;
}

static int duk_disasm(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int res = 0, res2 = 0;
	const char *opstr = NULL;
	ut8 *b = a->cur->user;
	duk_push_global_stash (ctx);
	duk_dup (ctx, 0);  /* timer callback */
	duk_get_prop_string (ctx, -2, "disfun");
	b = a->cur->user = duk_require_tval (ctx, -1);
//	pushBuffer (buf, len);
	if (duk_is_callable (ctx, -1)) {
		int i;
		// duk_push_string (ctx, "TODO 2");
		pushBuffer (buf, len);
		duk_call (ctx, 1);

		// [ size, str ]
		for (i = 0; i < 3; i++) {
			duk_dup_top (ctx);
			duk_get_prop_index (ctx, -1, i);
			if (duk_is_number (ctx, -1)) {
				if (res) {
					res2 = duk_to_number (ctx, -1);
				} else {
					res2 = res = duk_to_number (ctx, -1);
				}
			} else if (duk_is_string (ctx, -1)) {
				if (!opstr) {
					opstr = duk_to_string (ctx, -1);
				}
			}
			duk_pop (ctx);
		}
	} else {
		eprintf ("[:(] Is not a function %02x %02x\n", b[0],b[1]);
	}

	// fill op struct
	op->size = res;
	if (!opstr) opstr = "invalid";
	r_asm_op_set_asm (op, opstr);
	char *hexstr = malloc(op->size * 2);
	if (hexstr) {
		r_hex_bin2str (buf, op->size, hexstr);
		r_asm_op_set_hex (op, hexstr);
	}
	return res2;
}

static int r2plugin(duk_context *ctx) {
	RLibStruct *lib_struct;
	bool ret = true;
	// args: type, function
	const char *type = duk_require_string (ctx, 0);
	if (strcmp (type, "asm")) {
		eprintf ("TODO: duk.r2plugin only supports 'asm' plugins atm\n");
		return false;
	}
	// call function of 2nd parameter, or get object
	if (duk_is_function (ctx, 1)) {
		duk_push_string (ctx, "TODO"); // TODO: this must be the RAsm object to get bits, offset, ..
		duk_call (ctx, 1);
		duk_to_object (ctx, 1);
	}
	if (!duk_is_object (ctx, 1)) {
		eprintf ("Expected object or function\n");
		return false;
	}
	duk_to_object (ctx, 1);
	#define ap asm_plugin
	ap = R_NEW0 (RAsmPlugin);

#define GETSTR(x,y,or) \
	duk_dup_top (ctx); \
	duk_get_prop_string (ctx, 1, y); \
	if (or) { \
		const char *str = duk_to_string (ctx, -1); \
		x = mystrdup (str? str: or); \
	} else { \
		x = mystrdup (duk_require_string (ctx, -1)); \
	} \
	duk_pop (ctx);

#define GETINT(x,y,or) \
	duk_dup_top (ctx); \
	duk_get_prop_string (ctx, 1, y); \
	if (or) { \
		x = duk_is_number (ctx, -1)? \
			duk_to_int (ctx, -1): or; \
	} else { \
		x = duk_require_int (ctx, -1); \
	} \
	duk_pop (ctx);

#define GETFUN(x,y) \
	duk_dup_top (ctx); \
	duk_get_prop_string (ctx, 1, y); \
	x = duk_require_tval (ctx, 1); \
	duk_pop (ctx);

	// mandatory
	GETSTR (ap->name, "name", NULL);
	GETSTR (ap->arch, "arch", NULL);
	// optional
	GETSTR (ap->license, "license", "unlicensed");
	GETSTR (ap->desc, "description", "JS Disasm Plugin");
	GETINT (ap->bits, "bits", 32);
	// mandatory unless we handle asm+disasm
	ap->user = duk_require_tval (ctx, -1);
	//ap->user = duk_dup_top (ctx); // clone object inside user
	//GETFUN (ap->user, "disassemble");
	duk_push_global_stash(ctx);
	duk_get_prop_string (ctx, 1, "disassemble");
	duk_put_prop_string(ctx, -2, "disfun"); // TODO: prefix plugin name somehow
	ap->disassemble = duk_disasm;

	duk_push_global_stash(ctx);
	duk_get_prop_string (ctx, 1, "assemble");
	duk_put_prop_string(ctx, -2, "asmfun"); // TODO: prefix plugin name somehow
	ap->assemble = duk_assemble;

#if 0
	duk_get_prop_string (ctx, 1, "disassemble");
	duk_push_string (ctx, "WINRAR");
	duk_call (ctx, 1);
#endif
#if 0
	duk_get_prop_string (ctx, 1, "disassemble");
	void *a = duk_require_tval (ctx, -1);
	if (duk_is_callable (ctx, -1)) {
		ut8 *b = a;
		eprintf ("IS FUNCTION %02x %02x \n", b[0], b[1]);
	} else eprintf ("NOT CALLABLE\n");
	ap->user = a;
	eprintf ("---- %p\n", a);
	duk_push_string (ctx, "FUCK YOU");
	//duk_dup_top(ctx);
	//duk_call_method (ctx, 0);
	duk_call (ctx, 1);
	duk_push_tval (ctx, ap->user); // push fun
	duk_push_string (ctx, "WINRAR");
	duk_call (ctx, 1);
	duk_pop (ctx);
#endif

	// TODO: add support to assemble from js too
	//ap->assemble = duk_disasm;
	#define lp lib_struct
	lp = R_NEW0 (RLibStruct);
	lp->type = R_LIB_TYPE_ASM; // TODO resolve from handler
	lp->data = ap;
	r_lib_open_ptr (Gcore->lib, "duktape.js", NULL, lp);
	duk_push_boolean (ctx, ret);
	return 1;
}

static int r2cmd(duk_context *ctx) {
	char *ret;
	int n = duk_get_top (ctx);  /* #args */
	if (n>0) {
		const char *s = duk_to_string (ctx, 0);
		ret = r_core_cmd_str (Gcore, s);
		duk_push_string (ctx, ret);
		free (ret);
		return 1;
	}
	return 0;
}

#ifndef PREFIX
#define PREFIX "/usr"
#endif
static void register_r2cmd_duktape (RLang *lang, duk_context *ctx) {
	Gcore = lang->user;
	duk_push_global_object (ctx);

	duk_push_c_function (ctx, r2cmd, DUK_VARARGS);
	duk_put_prop_string (ctx, -2 /*idx:global*/, "r2cmd");

	duk_push_c_function (ctx, r2plugin, DUK_VARARGS);
	duk_put_prop_string (ctx, -2 /*idx:global*/, "r2plugin");

	duk_pop (ctx);  /* pop global */
//	lang_duktape_file (lang, "/tmp/r2.js"); ///usr/share/radare2/0.9.8.git/www/t/r2.js");
	lang_duktape_file (lang, PREFIX"/share/radare2/last/www/t/r2.js");
}

static void print_error(duk_context *ctx, FILE *f) {
	if (duk_is_object(ctx, -1) && duk_has_prop_string(ctx, -1, "stack")) {
		/* FIXME: print error objects specially */
		/* FIXME: pcall the string coercion */
		duk_get_prop_string (ctx, -1, "stack");
		if (duk_is_string (ctx, -1)) {
			fprintf (f, "%s\n", duk_get_string(ctx, -1));
			fflush (f);
			duk_pop_2 (ctx);
			return;
		} else {
			duk_pop (ctx);
		}
	}
	duk_to_string(ctx, -1);
	fprintf (f, "%s\n", duk_get_string(ctx, -1));
	fflush (f);
	duk_pop(ctx);
}

static int wrapped_compile_execute(duk_context *ctx, void *usr) {
	duk_compile (ctx, 0);
	duk_push_global_object (ctx);
	duk_call_method (ctx, 0);
// return value is stored here	duk_to_string(ctx, -1);
	duk_pop (ctx);
	return 0;
}

static bool lang_duktape_safe_eval(duk_context *ctx, const char *code) {
#if UNSAFE
	duk_eval_string (ctx, code);
#else
	bool rc;
	duk_push_lstring (ctx, code, strlen (code));
	duk_push_string (ctx, "input");
	rc = duk_safe_call (ctx, wrapped_compile_execute, NULL, 2, 1);
	if (rc != DUK_EXEC_SUCCESS) {
		print_error (ctx, stderr);
		rc = false;
	} else {
		duk_pop (ctx);
		rc = true;
	}
	return rc;
#endif
}

static void register_helpers(RLang *lang) {
	// TODO: move this code to init/fini
	if (is_init) {
		return;
	}
	is_init = 1;
	ctx = duk_create_heap_default ();
        duk_console_init(ctx, DUK_CONSOLE_PROXY_WRAPPER /*flags*/);
	register_r2cmd_duktape (lang, ctx);
#if  0
	lang_duktape_safe_eval (ctx,
		"var console = {log:print,error:print}");
#endif
	lang_duktape_safe_eval (ctx, "function dir(x){"
		"console.log(JSON.stringify(x).replace(/,/g,',\\n '));"
		"for(var i in x) {console.log(i);}}");
}

static int lang_duktape_run(RLang *lang, const char *code, int len) {
	register_helpers (lang);
	return lang_duktape_safe_eval (ctx, code);
}

static int lang_duktape_file(RLang *lang, const char *file) {
	int ret = -1;
	char *code = r_file_slurp (file, NULL); 
	if (code) {
		register_helpers (lang);
		duk_push_lstring (ctx, code, strlen (code));
		duk_push_string (ctx,file);
		free (code);
		ret = duk_safe_call (ctx, wrapped_compile_execute, NULL, 2, 1);
		if (ret != DUK_EXEC_SUCCESS) {
			print_error (ctx, stderr);
			eprintf ("duktape error");
		} else {
			duk_pop (ctx);
			ret = 1;
		}
	}
	return ret;
}

static RLangPlugin r_lang_plugin_duktape = {
	.name = "duktape",
	.ext = "duk",
	.desc = "JavaScript extension language using DukTape",
	.run = lang_duktape_run,
	.init = (void*)lang_duktape_init,
	.fini = (void*)lang_duktape_fini,
	.run_file = (void*)lang_duktape_file,
};

#if !CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_duktape,
	.version = R2_VERSION
};
#endif
