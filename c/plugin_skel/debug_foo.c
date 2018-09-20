#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <r_debug.h>

static int r_debug_foo_step(RDebug *dbg) {
    return 1;
}

// "dc" continue execution
static int r_debug_foo_continue(RDebug *dbg, int pid, int tid, int sig) {
    return 1;
}

static int r_debug_foo_attach(RDebug *dbg, int pid) {
    return 1;
}

static int r_debug_foo_detach(RDebug *dbg, int pid) {
    return 1;
}

static RList* r_debug_foo_threads(RDebug *dbg, int pid) {
    return NULL;
}

static RDebugReasonType r_debug_foo_wait(RDebug *dbg, int pid) {
    RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
    return reason;
}

// "dm" get memory maps of target process
static RList *r_debug_foo_map_get(RDebug* dbg) {
    return NULL;
}

static RList* r_debug_foo_modules_get(RDebug *dbg) {
    return NULL;
}

static int r_debug_foo_breakpoint (struct r_bp_t *bp, RBreakpointItem *b, bool set) {
    return 1;
}

// "drp" register profile
static const char *r_debug_foo_reg_profile(RDebug *dbg) {
    return NULL;
}

// "dk" send signal
static bool r_debug_foo_kill(RDebug *dbg, int pid, int tid, int sig) {
    return false;
}

static int r_debug_foo_select(int pid, int tid) {
    return 1;
}

static RDebugInfo* r_debug_foo_info(RDebug *dbg, const char *arg) {
    return NULL;
}

static RList* r_debug_foo_frames(RDebug *dbg, ut64 at) {
    return NULL;
}

static int r_debug_foo_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
    return 1;
}

RDebugPlugin r_debug_plugin_foo = {
    .name = "foo",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .canstep = 1,
    .info = &r_debug_foo_info,
    .attach = &r_debug_foo_attach,
    .detach = &r_debug_foo_detach,
    .select = &r_debug_foo_select,
    .threads = &r_debug_foo_threads,
    .step = &r_debug_foo_step,
    .cont = &r_debug_foo_continue,
    .wait = &r_debug_foo_wait,
    .kill = &r_debug_foo_kill,
    .frames = &r_debug_foo_frames,
    .reg_read = &r_debug_foo_reg_read,
    .reg_profile = (void*) &r_debug_foo_reg_profile,
    .map_get = &r_debug_foo_map_get,
    .modules_get = &r_debug_foo_modules_get,
    .breakpoint = &r_debug_foo_breakpoint,
};


#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_DBG,
    .data = &r_debug_plugin_foo,
    .version = R2_VERSION
};
#endif
