'use strict';

// Minimal radare2 bindings for Node.js, backed by koffi.
// The valabind-generated r_core.js (produced by `make`) covers the full vapi
// surface; this hand-written entry point exposes the subset the examples and
// the CI smoke test use. Keeping it focused lets the bindings load on any
// Node >= 16 without native rebuilds.

const koffi = require('koffi');

const soext = process.platform === 'darwin' ? '.dylib'
           : process.platform === 'win32' ? '.dll'
           : '.so';

function loadLib(name) {
    const candidates = [name + soext, name + soext + '.0', name];
    let lastError;
    for (const candidate of candidates) {
        try {
            return koffi.load(candidate);
        } catch (e) {
            lastError = e;
        }
    }
    throw lastError;
}

const rcore = loadLib('libr_core');
const rcons = loadLib('libr_cons');

const RCorePtr = 'void *';

const r_core_new = rcore.func('r_core_new', RCorePtr, []);
const r_core_free = rcore.func('r_core_free', 'void', [RCorePtr]);
const r_core_cmd0 = rcore.func('r_core_cmd0', 'int', [RCorePtr, 'str']);
const r_core_cmd_str = rcore.func('r_core_cmd_str', 'str', [RCorePtr, 'str']);
const r_core_file_open = rcore.func('r_core_file_open', 'void *',
    [RCorePtr, 'str', 'int', 'uint64']);
const r_core_bin_load = rcore.func('r_core_bin_load', 'bool',
    [RCorePtr, 'str', 'uint64']);
const r_core_seek = rcore.func('r_core_seek', 'bool',
    [RCorePtr, 'uint64', 'bool']);
const r_core_block_read = rcore.func('r_core_block_read', 'int', [RCorePtr]);

const r_cons_flush = rcons.func('r_cons_flush', 'void', []);
const r_cons_reset = rcons.func('r_cons_reset', 'void', []);

class RCore {
    constructor() {
        this._ptr = r_core_new();
        if (!this._ptr) {
            throw new Error('r_core_new() returned null');
        }
    }

    free() {
        if (this._ptr) {
            r_core_free(this._ptr);
            this._ptr = null;
        }
    }

    cmd0(cmd) { return r_core_cmd0(this._ptr, cmd); }
    cmd_str(cmd) { return r_core_cmd_str(this._ptr, cmd); }
    file_open(path, flags = 0, offset = 0n) {
        return r_core_file_open(this._ptr, path, flags, BigInt(offset));
    }
    bin_load(path, offset = 0n) {
        return r_core_bin_load(this._ptr, path, BigInt(offset));
    }
    seek(addr, rb = true) {
        return r_core_seek(this._ptr, BigInt(addr), rb);
    }
    block_read() { return r_core_block_read(this._ptr); }
}

const RCons = {
    flush: () => r_cons_flush(),
    reset: () => r_cons_reset(),
};

module.exports = { RCore, RCons, koffi };
