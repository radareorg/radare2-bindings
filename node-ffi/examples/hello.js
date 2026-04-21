'use strict';

const r2 = require('..');

const core = new r2.RCore();
const fileName = process.argv[2] || '/bin/ls';

const file = core.file_open(fileName, 0, 0n);
if (!file) {
    console.error('Cannot open ' + fileName);
    process.exit(1);
}

core.bin_load(null, 0n);

console.log('-- hello from radare2.js --');
console.log('file:', fileName);
console.log('-- pd 3 --');
console.log(core.cmd_str('pd 3'));
console.log('-- ?e hello --');
console.log(core.cmd_str('?e hello'));

core.free();
