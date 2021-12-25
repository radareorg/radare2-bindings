package org.radare2.struct;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.io.Closeable;
import org.radare2.library.r_asm;
import org.radare2.utils.StringUtils;

@Structure.FieldOrder({"user"})
public class RAsm extends Structure implements Closeable {

    public Pointer user; // unused, given to avoid shitty exceptions from jna

    public static RAsm getInstance() {
        return r_asm.instance.r_asm_new();
    }

    public int set_pc(long addr) {
        return r_asm.instance.r_asm_set_pc(this, addr);
    }

    public boolean set_big_endian(boolean big) {
        return r_asm.instance.r_asm_set_big_endian(this, big ? 1 : 0) == 1;
    }

    public int set_syntax_from_string(String syn) {
        return r_asm.instance.r_asm_syntax_from_string(this, syn);
    }
	
	public boolean use(String arch){
		return r_asm.instance.r_asm_use(this,arch)==1;
	}
	
	public int set_bits(int bits){
		return r_asm.instance.r_asm_set_bits(this,bits);
	}

    public boolean set_arch(String arch, int bits) {
        return r_asm.instance.r_asm_set_arch(this, arch, bits) == 1;
    }

    public boolean is_valid(String str) {
        return r_asm.instance.r_asm_is_valid(this, str) == 1;
    }

    public boolean use_assembler(String asmblr) {
        return r_asm.instance.r_asm_use_assembler(this, asmblr) == 1;
    }

    public RAsmOp disassemble(String hex) {
        RAsmOp aop = RAsmOp.getInstance();
        r_asm.instance.r_asm_disassemble(
                this, aop, StringUtils.fromHexString(hex), hex.length() / 2);
        return aop;
    }

    public RAsmOp assemble(String asm) {
        RAsmOp aop = RAsmOp.getInstance();
        r_asm.instance.r_asm_assemble(this, aop, asm);
        return aop;
    }

    // try with resources, autocloseable

    public void close() {
        r_asm.instance.r_asm_free(this);
    }
}
