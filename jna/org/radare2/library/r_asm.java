package org.radare2.library;

import com.sun.jna.*;
import org.radare2.struct.*;

public interface r_asm extends Library {

    r_asm instance = Native.load("r_asm", r_asm.class);

    RAsm r_asm_new();

    int r_asm_set_pc(RAsm self, long addr);

    int r_asm_set_big_endian(RAsm self, int bool);

    int r_asm_syntax_from_string(RAsm self, String syn);

    int r_asm_use(RAsm self,String arch);
	
	int r_asm_set_bits(RAsm self,int bits);
	
    int r_asm_set_arch(RAsm self, String arch, int bits);

    int r_asm_is_valid(RAsm self, String str);

    int r_asm_use_assembler(RAsm self, String asmblr);

    int r_asm_disassemble(RAsm self, RAsmOp aop, byte[] data, int len);

    int r_asm_assemble(RAsm self, RAsmOp aop, String assembly);

    void r_asm_free(RAsm ras);

    RAsmOp r_asm_op_new();

    Pointer r_asm_op_get_hex(RAsmOp aop);

    Pointer r_asm_op_get_asm(RAsmOp aop);

    int r_asm_op_get_size(RAsmOp aop);

    void r_asm_op_free(RAsmOp aop);
	
}
