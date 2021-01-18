using GLib;
using Radare; /* Radare.Hash */

public class SyscallExample
{
	public static void main(string[] args)
	{
		var sc = new RSyscall();
		sc.setup ("x86", 32, "", "linux");
		var scn = sc.get_num("write");
		if (scn != 4) {
			assert(false);
		}
		print ("write = %d\n", scn);
	}
}
