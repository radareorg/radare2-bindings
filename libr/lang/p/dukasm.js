/*
 * Example disassembler plugin in Javascript for r2
 * This script depends on "duktape"
 * $ r2 -nqc '. dukasm.js' -
 */

var res = r2plugin ("asm", function (a) {
	function disassemble (buf) {
		switch (buf[0]) {
		case 0x90: return [1, "nop"];
		case 0xcc: return [1, "int3"];
		case 0xcd: return [2, "int "+buf[1]];
		}
		return [ 1, "invalid "+buf[0], -1 ];
	}
	function assemble(str) {
		var op = str.split (/ /g);
		switch (op[0]) {
		case "nop": return [0x90];
		case "int3": return [0xcc];
		case "int": return [0xcd, +op[1]];
		}
		return null;
	}
	return {
		name: "MyJS",
		arch: "myarch",
		license: "LGPL3",
		bits: 32,
		description: "My Javascript Disassembler",
		disassemble: disassemble,
		assemble: assemble
	}
});

var msg = res? "New":"Error registering";
console.log (msg+" disasm plugin from Javascript");

if (res) {
	r2cmd ("e asm.arch=MyJS");
	r2cmd ("wx 0090cccd33");
	console.log (r2cmd ("pd 4"));
	console.log (r2cmd ("\"pa nop;int3\""));
}
