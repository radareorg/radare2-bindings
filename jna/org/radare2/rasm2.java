package org.radare2;

import com.sun.jna.*;
import java.io.Closeable;
import org.radare2.library.*;
import org.radare2.struct.*;

public class rasm2 implements Closeable {

	private RAsm ras = RAsm.getInstance();

	public int set_pc(long addr) {
		return ras.set_pc(addr);
	}

	public boolean set_big_endian(boolean big) {
		return ras.set_big_endian(big);
	}

	/* syntax name is after SYNTAX_ and should be in small letters */

	/*
	enum {
		R_ASM_SYNTAX_NONE = 0,
		R_ASM_SYNTAX_INTEL,
		R_ASM_SYNTAX_ATT,
		R_ASM_SYNTAX_MASM,
		R_ASM_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
		R_ASM_SYNTAX_JZ, // hack to use jz instead of je on x86
	};
	
	*/

	public int set_syntax_from_string(String syn) {
		return ras.set_syntax_from_string(syn);
	}

	/* arch name is after plugin_ and replace any "_" after that with "." */

	/*
	extern RAsmPlugin r_asm_plugin_6502;
	extern RAsmPlugin r_asm_plugin_8051;
	extern RAsmPlugin r_asm_plugin_amd29k;
	extern RAsmPlugin r_asm_plugin_arc;
	extern RAsmPlugin r_asm_plugin_arm_as;
	extern RAsmPlugin r_asm_plugin_arm_cs;
	extern RAsmPlugin r_asm_plugin_arm_gnu;
	extern RAsmPlugin r_asm_plugin_arm_winedbg;
	extern RAsmPlugin r_asm_plugin_avr;
	extern RAsmPlugin r_asm_plugin_null;
	extern RAsmPlugin r_asm_plugin_cr16;
	extern RAsmPlugin r_asm_plugin_cris_gnu;
	extern RAsmPlugin r_asm_plugin_dalvik;
	extern RAsmPlugin r_asm_plugin_dcpu16;
	extern RAsmPlugin r_asm_plugin_gb;
	extern RAsmPlugin r_asm_plugin_h8300;
	extern RAsmPlugin r_asm_plugin_hppa_gnu;
	extern RAsmPlugin r_asm_plugin_i8080;
	extern RAsmPlugin r_asm_plugin_java;
	extern RAsmPlugin r_asm_plugin_lanai_gnu;
	extern RAsmPlugin r_asm_plugin_lh5801;
	extern RAsmPlugin r_asm_plugin_lm32;
	extern RAsmPlugin r_asm_plugin_m680x_cs;
	extern RAsmPlugin r_asm_plugin_malbolge;
	extern RAsmPlugin r_asm_plugin_mcs96;
	extern RAsmPlugin r_asm_plugin_mips_cs;
	extern RAsmPlugin r_asm_plugin_mips_gnu;
	extern RAsmPlugin r_asm_plugin_nios2;
	extern RAsmPlugin r_asm_plugin_or1k;
	extern RAsmPlugin r_asm_plugin_pic;
	extern RAsmPlugin r_asm_plugin_ppc_as;
	extern RAsmPlugin r_asm_plugin_ppc_cs;
	extern RAsmPlugin r_asm_plugin_propeller;
	extern RAsmPlugin r_asm_plugin_riscv;
	extern RAsmPlugin r_asm_plugin_riscv_cs;
	extern RAsmPlugin r_asm_plugin_rsp;
	extern RAsmPlugin r_asm_plugin_sh;
	extern RAsmPlugin r_asm_plugin_sparc_cs;
	extern RAsmPlugin r_asm_plugin_sparc_gnu;
	extern RAsmPlugin r_asm_plugin_tms320;
	extern RAsmPlugin r_asm_plugin_tricore;
	extern RAsmPlugin r_asm_plugin_v810;
	extern RAsmPlugin r_asm_plugin_v850;
	extern RAsmPlugin r_asm_plugin_m68k_gnu;
	extern RAsmPlugin r_asm_plugin_x86_as;
	extern RAsmPlugin r_asm_plugin_x86_cs;
	extern RAsmPlugin r_asm_plugin_x86_nasm;
	extern RAsmPlugin r_asm_plugin_x86_nz;
	extern RAsmPlugin r_asm_plugin_xap;
	extern RAsmPlugin r_asm_plugin_xcore_cs;
	extern RAsmPlugin r_asm_plugin_xtensa;
	extern RAsmPlugin r_asm_plugin_pyc;
	extern RAsmPlugin r_asm_plugin_pdp11_gnu;
	extern RAsmPlugin r_asm_plugin_alpha;
	extern RAsmPlugin r_asm_plugin_vasm;
	*/

	public boolean use(String arch) {
		return ras.use(arch);
	}

	/* 8, 16, 32, 64 */

	public int set_bits(int bits) {
		return ras.set_bits(bits);
	}

	public boolean set_arch(String arch, int bits) {
		return ras.set_arch(arch, bits);
	}

	public boolean is_valid(String str) {
		return ras.is_valid(str);
	}

	public boolean use_assembler(String asmblr) {
		return ras.use_assembler(asmblr);
	}

	public RAsmOp disassemble(String hex) {
		return ras.disassemble(hex);
	}

	public RAsmOp assemble(String asm) {
		return ras.assemble(asm);
	}

	// the rasm2 instance should not be used after calling close

	public void close() {
		ras.close();
	}
}
