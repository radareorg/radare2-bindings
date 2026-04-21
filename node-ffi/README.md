radare2.js
==========
Node.js bindings for radare2.

- `index.js` is a handwritten [koffi](https://koffi.dev) wrapper that exposes
  the subset of the C API used by the examples — it loads `libr_core` and
  `libr_cons` directly and works on any modern Node (no native rebuild step).
- `r_core.js`, `r_bin.js`, `r_asm.js`, `r_io.js` are generated from the vapi
  files under `../vapi/` with `valabind --node-ffi`. They are kept as
  reference bindings for the full API surface.

Install
-------

```
make          # generates r_*.js from vapi + installs npm deps
make test     # runs the hello smoke test against /bin/ls
```

Usage
-----

```js
const r2 = require('radare2.js');
const core = new r2.RCore();
core.file_open('/bin/ls', 0, 0n);
core.bin_load(null, 0n);
console.log(core.cmd_str('pd 5'));
core.free();
```
