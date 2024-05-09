uses
	Radare

init
	var st = new RAsm()
	st.use("mips")
	// st.set_syntax(RAsm.Syntax.INTEL)
	st.set_bits(64)
	st.set_big_endian(true)
	st.set_pc(0x8048000)

	/* Disassembler test */
	var op = new RAnal.Op()
	// var buf = "\x83\xe4\xf0\x20"
	var buf = "\x41\x55\x41\x54"
	var res = st.disassemble(op, buf, 4)
	print "result: %d", res
	print "opcode: %s", op.mnemonic
	// print "bytes: %s", op.buf_hex
	print "length: %d", op.size
