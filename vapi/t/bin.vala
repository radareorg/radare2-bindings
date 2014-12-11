/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

using Radare;

public void main (string[] args) { 
	if (args.length != 2)
		error ("Usage: %s <file>\n", args[0]);

	var path = args[1];
	var io = new RIO ();
	var desc = io.open(path,0,0);
	var bin = new RBin ();
	bin.iobind (io);
	if (bin.load (args[1], 0,0,0,desc.fd,0) != 1)
		error ("Cannot open binary file\n");

	uint64 baddr = bin.get_baddr();
	print ("Base addr: 0x%08"+uint64.FORMAT_MODIFIER+"x\n", baddr);
	foreach (var sym in bin.get_symbols ())
		print ("0x%08"+uint64.FORMAT_MODIFIER+"x - %s\n",
			baddr+sym.vaddr, sym.name);
	foreach (var sec in bin.get_sections())
		print ("0x%08"+uint64.FORMAT_MODIFIER+"x - %s\n",
			baddr+sec.vaddr, sec.name);
}
