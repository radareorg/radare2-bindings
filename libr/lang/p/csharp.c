/* radare - MIT - Copyright 2016 pancake */

#define _XOPEN_SOURCE 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>

static int lang_csharp_run(RLang *lang, const char *code, int len) {
	lang->cmdf (lang->user, "#!pipe csharp-r2 -e '%s'", code);
	return 1;
}

static int lang_csharp_prompt(RLang *lang) {
	lang->cmdf (lang->user, "#!pipe csharp-r2");
	return 1;
}

static bool lang_csharp_file(RLang *lang, const char *file) {
	int ret = false;
	if (lang && lang->cmdf && file) {
		lang->cmdf (lang->user, "#!pipe csharp-r2 -i '%s'", file);
		return true;
	}
	return true;
}

static RLangPlugin r_lang_plugin_csharp = {
	.name = "csharp",
	.ext = "cs",
	.desc = "C# extension language using Mono",
	.license = "MIT",
	.prompt = lang_csharp_prompt,
	.run = lang_csharp_run,
	.run_file = (void*)lang_csharp_file,
};

#if !CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_csharp,
};
#endif
