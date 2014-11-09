using Radare;

public static void main(string[] args)
{
	var c = new RCore();
	//var b = new RBin();
	c.file_open("/bin/ls", 0);
	c.bin.load("/bin/ls", 0, 0, 0, 0, 0);
	uint64 baddr = c.bin.get_baddr();
	foreach (var scn in c.bin.get_sections())
		if ((scn.srwx & 0x1) != 0)
				foreach (var hit in c.asm_strsearch("jmp e; ret", scn.paddr , scn.paddr+scn.size))
					print("0x%08"+uint64.FORMAT_MODIFIER+"x - %s\n", baddr+hit.addr, hit.code);
}
