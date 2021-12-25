package org.radare2.struct;

import com.sun.jna.Structure;
import java.io.Closeable;
import org.radare2.library.r_asm;

@Structure.FieldOrder({"payload"})
public class RAsmOp extends Structure implements Closeable {

    public int payload; // unused, given for avoiding exceptions

    public static RAsmOp getInstance() {
        return r_asm.instance.r_asm_op_new();
    }

    public String get_hex() {
        return r_asm.instance.r_asm_op_get_hex(this).getString(0);
    }

    public String get_asm() {
        return r_asm.instance.r_asm_op_get_asm(this).getString(0);
    }

    public int get_size() {
        return r_asm.instance.r_asm_op_get_size(this);
    }

    // autoclosable with try with resources
    public void close() {
        r_asm.instance.r_asm_op_free(this);
    }
}
