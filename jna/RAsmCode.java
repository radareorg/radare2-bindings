import java.util.List;
import java.util.Arrays;
import com.sun.jna.Structure;

public class RAsmCode extends Structure {
	public int len;
	public String buf;
	public String buf_hex;
	public String buf_asm;

	protected List<String> getFieldOrder() {
		return Arrays.asList (
			"len", "buf", "buf_hex", "buf_asm"
		);
	}
}
