/* radare - LGPL - Copyright 2020 pancake */

#define _XOPEN_SOURCE 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>

#include "./quickjs/quickjs.h"

static RCore *Gcore = NULL;
static JSContext *ctx = NULL;
static bool is_init = false;
#define countof(x) (sizeof(x) / sizeof((x)[0]))

static JSValue r2log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2(ctx, &plen, argv[0], false);
	eprintf ("%s\n", n);
	return JS_NewBool (ctx, true);
}

static JSValue r2cmd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
	size_t plen;
	const char *n = JS_ToCStringLen2(ctx, &plen, argv[0], false);
	char *ret = r_core_cmd_str (Gcore, n);
	return JS_NewString (ctx, ret);
}

static const JSCFunctionListEntry js_r2_funcs[] = {
	JS_CFUNC_DEF("cmd", 1, r2cmd),
	JS_CFUNC_DEF("log", 1, r2log),
};

static int js_r2_init(JSContext *ctx, JSModuleDef *m) {
	return JS_SetModuleExportList(ctx, m, js_r2_funcs, countof (js_r2_funcs));
}

static void js_dump_obj(JSContext *ctx, FILE *f, JSValueConst val)
{
    const char *str;

    str = JS_ToCString(ctx, val);
    if (str) {
        fprintf(f, "%s\n", str);
        JS_FreeCString(ctx, str);
    } else {
        fprintf(f, "[exception]\n");
    }
}

static void js_std_dump_error1(JSContext *ctx, JSValueConst exception_val)
{
    JSValue val;
    bool is_error;

    is_error = JS_IsError(ctx, exception_val);
    js_dump_obj(ctx, stderr, exception_val);
    if (is_error) {
        val = JS_GetPropertyStr(ctx, exception_val, "stack");
        if (!JS_IsUndefined(val)) {
            js_dump_obj(ctx, stderr, val);
        }
        JS_FreeValue(ctx, val);
    }
}
void js_std_dump_error(JSContext *ctx)
{
    JSValue exception_val;
    
    exception_val = JS_GetException(ctx);
    js_std_dump_error1(ctx, exception_val);
    JS_FreeValue(ctx, exception_val);
}

static void register_helpers(RLang *lang) {
	// TODO: move this code to init/fini
	if (ctx != NULL || is_init) {
		return;
	}
	is_init = true;
	Gcore = lang->user;
	JSRuntime *rt = JS_NewRuntime();
	ctx = JS_NewContext (rt);
	JSModuleDef *m = JS_NewCModule (ctx, "r2", js_r2_init);
	if (!m) {
		return ;
	}
	js_r2_init (ctx, m);
	JS_AddModuleExportList(ctx, m, js_r2_funcs, countof(js_r2_funcs));
#if 0
	eval(ctx, "function dir(x){"
		"console.log(JSON.stringify(x).replace(/,/g,',\\n '));"
		"for(var i in x) {console.log(i);}}");
#endif
}


static int eval(JSContext *ctx, const char *code) {
	JSValue v = JS_Eval (ctx, code, strlen (code), "-", 0);
	if (JS_IsException(v)) {
		js_std_dump_error (ctx);
		JSValue e = JS_GetException (ctx);
	}
	return -1;
}

static int lang_quickjs_run(RLang *lang, const char *code, int len) {
	register_helpers (lang);
	return eval (ctx, code);
}

static int lang_quickjs_file(RLang *lang, const char *file) {
	int rc = -1;
	register_helpers (lang);
	char *code = r_file_slurp (file, NULL); 
	if (code) {
		rc = eval (ctx, code);
		free (code);
	}
	return rc;
}

static RLangPlugin r_lang_plugin_quickjs = {
	.name = "quickjs",
	.ext = "qjs",
	.desc = "JavaScript extension language using QuicKJS",
	.run = lang_quickjs_run,
	.run_file = (void*)lang_quickjs_file,
};

#if !CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_quickjs,
	.version = R2_VERSION
};
#endif
