import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;


public class AsmExample {
	public static void main(String[] args) {
		RAsm a = new RAsm ();
		a.use ("x86");
		a.set_bits (32);
		RAsmCode code = a.mdisassemble_hexstr ("909090");
		System.out.println ("LEN "+ code.len);
		System.out.println ("CODE "+ code.buf_asm);

		code = a.massemble ("mov eax, 33");
		System.out.println ("HEX "+code.buf_hex);
	}
}
