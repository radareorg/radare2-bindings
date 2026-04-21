/* radare - LGPL - Copyright 2010-2024 - pancake */

namespace Radare {
/**
 * Radare2 Assembler Module
 */
[Compact]
[CCode (cheader_filename="r_asm.h", cname="RAsm", free_function="r_asm_free", cprefix="r_asm_")]
public class RAsm {
	/**
	 * Architectures supported.
	 */
	[CCode (cprefix="R_SYS_ARCH_", cname="int")]
	public enum Arch {
		NONE,
		X86,
		ARM,
		PPC,
		M68K,
		JAVA,
		MIPS,
		SPARC,
		XAP,
		MSIL,
		OBJD,
		BF,
		SH,
		AVR,
		DALVIK,
		Z80,
		ARC,
		I8080,
		RAR
	}

	/**
	 * The supported assembler syntax variations.
	 */
	[CCode (cprefix="R_ARCH_SYNTAX_", cname="int")]
	public enum Syntax {
		/**
		 * Use default syntax provided by the disassembler
		 */
		NONE,
		/**
		 * Intel syntax
		 */
		INTEL,
		/**
		 * AT&T syntax
		 */
		ATT,
		/**
		 * Microsoft Assembler syntax
		 */
		MASM,
		/**
		 * Always use numeric registers
		 */
		REGNUM,
		/**
		 * Use JZ instead of JE on x86
		 */
		JZ
	}

	/* R_ASM_MOD_* was removed from radare2 */

	/**
	 * Models decompiled assembly code.
	 */
	[Compact]
	[CCode (cname="RAsmCode", cprefix="r_asm_code_", free_function="r_asm_code_free", unref_function="r_asm_code_free")]
	public class Code {
		int len;
		uint8 bytes;
		string assembly;
		// RList equs
		uint64 code_offset;
		uint64 data_offset;
		int code_align;
		//public string buf_hex;
		public string get_hex();
		public string equ_replace(string s);
		public void set_equ(string k, string v);
	}

	/**
	 * The syntax.
	 */
	// public Syntax syntax;
	public uint64 pc;

	public RAsm();
	public bool use(string name);
/*
	public bool set_arch(string name, int bits);
*/
	public bool set_pc(uint64 addr);
	public bool set_bits(int bits);
	public bool set_big_endian(bool big);
	//public bool set_syntax(Syntax syntax);
	// TODO: Use Code? instead of op??
	public int disassemble(RAnal.Op op, uint8* buf, int length);
	/**
	 * Assemble the provided string into a Code block.
	 */
	public Code? assemble(string buf);
	public Code? mdisassemble(uint8 *buf, int length);
	[CCode (cname="r_asm_assemble")]
	public Code? massemble(string buf);
	// public Code? assemble_file(string file);

	public string tostring(uint64 addr, uint8* buf, int len);
	public uint8* from_string(uint64 addr, string str, out int len);

	/* TODO: not directy defined here */
	public void free();

	/**
	 * Represents Radare2 assembly plugins.
	 */
	[Compact]
	[CCode (cname="RAsmPlugin", destroy_function="", free_function="")]
	public class Plugin {
	}
}
}
