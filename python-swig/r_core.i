/* SWIG interface for radare2's RCore API.
 * Hand-written — does NOT depend on valabind or r2 .vapi files.
 * Build: swig -python -c++ r_core.i && compile _r_core.so against libr_core.
 */
%module r_core

%{
#include <r_core.h>
%}

%include <stdint.i>

/* Opaque r2 types we pass around as pointers. */
%nodefaultctor RCore;
%nodefaultdtor RCore;
typedef struct r_core_t RCore;

%nodefaultctor RIODesc;
%nodefaultdtor RIODesc;
typedef struct r_io_desc_t RIODesc;

%nodefaultctor RBin;
%nodefaultdtor RBin;
typedef struct r_bin_t RBin;

%nodefaultctor RConfig;
%nodefaultdtor RConfig;
typedef struct r_config_t RConfig;

typedef uint64_t ut64;
typedef int64_t  st64;
typedef uint8_t  ut8;

/* Tell SWIG that r_core_cmd_str-style returns are heap strings it must free. */
%typemap(newfree) char * "free($1);";
%newobject r_core_cmd_str;
%newobject r_core_cmd_str_r;
%newobject r_core_cmd_str_pipe;
%newobject r_core_prompt_format;

/* Lifecycle. */
RCore *r_core_new(void);
void   r_core_free(RCore *core);
bool   r_core_init(RCore *core);

/* Command execution — the main reason you'd use libr_core from Python. */
int   r_core_cmd0(RCore *core, const char *cmd);
int   r_core_cmd(RCore *core, const char *cmd, bool log);
char *r_core_cmd_str(RCore *core, const char *cmd);
char *r_core_cmd_str_r(RCore *core, const char *cmd);
char *r_core_cmd_str_pipe(RCore *core, const char *cmd);
bool  r_core_cmd_file(RCore *core, const char *file);

/* File & binary loading. */
RIODesc *r_core_file_open(RCore *core, const char *file, int flags, ut64 loadaddr);
bool     r_core_bin_load(RCore *core, const char *file, ut64 baseaddr);
bool     r_core_bin_load_structs(RCore *core, const char *file);

/* Seek. */
bool r_core_seek(RCore *core, ut64 addr, bool rb);
int  r_core_seek_delta(RCore *core, st64 addr);
int  r_core_seek_align(RCore *core, ut64 align, int count);

/* Prompt / interactive. */
int  r_core_prompt(RCore *core, int sync);
int  r_core_prompt_exec(RCore *core);
bool r_core_prompt_loop(RCore *core);

/* Convenience: expose a field-accessor-style helper so Python code can grab
 * the current seek offset without going through "s" commands. We use %inline
 * so SWIG compiles the body straight into the wrapper. */
%inline %{
ut64 r_core_get_offset(RCore *core) {
    return core ? core->addr : 0;
}
%}
