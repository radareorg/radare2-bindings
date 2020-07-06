/* radare - LGPL - Copyright 2010-2015 pancake */

[Compact]
[CCode (cheader_filename="r_util/r_print.h", cprefix="r_print_", cname="RPrint", free_function="r_print_free")]
public class Radare.RPrint {
	/* constructor */
	public RPrint();

	/* fields */
	public int width;
	// public bool interrupt;
	public int limit;
	public bool cur_enabled;
	public int cur;
	public int ocur;
	public int flags;
	//public string datefmt;

	/* methods */
	public string hexpair (string str, int idx);
	public void set_flags (int flags);
	public void hexdump(uint64 addr, uint8* buf, int len, int baddr, int step, int foo);
	public void hexpairs(uint64 addr, uint8 *buf, int len);
	public void bytes(uint8* buf, int len, string fmt);
	//public void @byte (string fmt, int idx, uint8 ch);
	public void c(uint8 *buf, int len);
	public void raw(uint64 addr, uint8 *buf, int len, int lines);
	public void cursor(int cur,int len, int set);
	public void set_cursor(int curset, int ocursor, int cursor);
	public void code(uint64 addr, uint8* buf, int len, char lang);
	//public void string(uint64 addr, uint8* buf, int len);
	public int date_dos(uint8* buf, int len);
	public int date_w32(uint8* buf, int len);
	public int date_unix(uint8* buf, int len);
}
