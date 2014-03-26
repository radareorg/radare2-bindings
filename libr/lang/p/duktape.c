/* radare - LGPL - Copyright 2014 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#include "./duk/duktape.c"

static int lang_duktape_file(RLang *lang, const char *file);

static int lang_duktape_init(void *user) {
	return R_TRUE;
}

static int lang_duktape_fini(void *user) {
	return R_TRUE;
}

static RCore *Gcore = NULL;
static duk_context *ctx;
static int is_init = 0;

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
	duk_pop (ctx);  /* pop global */
//	lang_duktape_file (lang, "/tmp/r2.js"); ///usr/share/radare2/0.9.8.git/www/t/r2.js");
	lang_duktape_file (lang, PREFIX"/share/radare2/last/www/t/r2.js");
}

static void print_error(duk_context *ctx, FILE *f) {
	if (duk_is_object(ctx, -1) && duk_has_prop_string(ctx, -1, "stack")) {
		/* FIXME: print error objects specially */
		/* FIXME: pcall the string coercion */
		duk_get_prop_string(ctx, -1, "stack");
		if (duk_is_string(ctx, -1)) {
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

static int wrapped_compile_execute(duk_context *ctx) {
	duk_compile (ctx, 0);
	duk_push_global_object (ctx);
	duk_call_method (ctx, 0);
// return value is stored here	duk_to_string(ctx, -1);
	duk_pop (ctx);
	return 0;
}

static int lang_duktape_safe_eval(duk_context *ctx, const char *code) {
#if UNSAFE
	duk_eval_string (ctx, code);
#else
	int rc;
	duk_push_lstring (ctx, code, strlen (code));
	duk_push_string (ctx, "input");
	rc = duk_safe_call (ctx, wrapped_compile_execute, 2, 1, DUK_INVALID_INDEX);
	if (rc != DUK_EXEC_SUCCESS) {
		print_error(ctx, stderr);
		rc = R_FALSE;
	} else {
		duk_pop (ctx);
		rc = R_TRUE;
	}
	return rc;
#endif
}

static int lang_duktape_run(RLang *lang, const char *code, int len) {
	// TODO: move this code to init/fini
	if (!is_init) {
		ctx = duk_create_heap_default();
		register_r2cmd_duktape (lang, ctx);
		is_init = 1;
	}
	lang_duktape_safe_eval (ctx, "function dir(x){"
		"print(JSON.stringify(x).replace(/,/g,',\\n '));"
		"for(var i in x) {print(i);}}");
	return lang_duktape_safe_eval (ctx, code);
}

static int lang_duktape_file(RLang *lang, const char *file) {
	int ret = -1;
	char *code = r_file_slurp (file, NULL); 
	if (code) {
		lang_duktape_safe_eval (ctx, code);
		free (code);
	}
	return ret;
}

static RLangPlugin r_lang_plugin_duktape = {
	.name = "duktape",
	.ext = "js",
	.desc = "JavaScript extension language using DukTape",
	.help = NULL,
	.run = lang_duktape_run,
	.init = (void*)lang_duktape_init,
	.fini = (void*)lang_duktape_fini,
	.run_file = (void*)lang_duktape_file,
	.set_argv = NULL,
};

#if !CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_duktape,
};
#endif
