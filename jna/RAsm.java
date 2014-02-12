import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class RAsm {
	public interface C extends Library {
		C lib = (C) Native.loadLibrary ("r_asm", C.class);
		Pointer r_asm_new ();
		int r_asm_use (Pointer p, String s);
		int r_asm_set_bits (Pointer p, int b);
		RAsmCode r_asm_mdisassemble_hexstr (Pointer p, String s);
		RAsmCode r_asm_massemble (Pointer p, String s);
	}

	Pointer self = null;
	public RAsm() {
		self = C.lib.r_asm_new ();
	}
	public boolean use (String str) {
		return (C.lib.r_asm_use (self, str) == 1);
	}
	public boolean set_bits (int b) {
		return (C.lib.r_asm_set_bits (self, b) == 1);
	}
	public RAsmCode mdisassemble_hexstr (String s) {
		return C.lib.r_asm_mdisassemble_hexstr (self, s);
	}
	public RAsmCode massemble(String s) {
		return C.lib.r_asm_massemble (self, s);
	}
}
