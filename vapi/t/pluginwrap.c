#include <r_cmd.h>
#include <r_lib.h>

extern int mycall(void *user, const char *cmd);

static struct r_core_plugin_t plugindata = {
	"plgname",
	"my plugin description",
	mycall
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &plugindata
};
