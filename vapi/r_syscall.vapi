/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */


[Compact]
[CCode (cheader_filename="r_syscall.h", cname="RSyscall", free_function="r_syscall_free", cprefix="r_syscall_")]
public class Radare.RSyscall {
	[CCode (cname="RSyscallItem", free_function="r_syscall_item_free", unref_function="")]
	public class Item {
		string name;
		int swi;
		int num;
		int args;
		string sargs;
	}

	public Item item_new_from_string(string name, string s);

	public RSyscall();
	public bool setup(string arch, int bits, string cpu, string os);
	public unowned Item get(int num, int swi);
	public int get_num(string str);
	public unowned string sysreg(string name, uint64 num);
	//public unowned Item get_n(int num);
	public unowned string get_i(int num, int swi);
	public Radare.RList<string> list();
}
