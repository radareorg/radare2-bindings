/* radare - LGPL - Copyright 2009-2013 - pancake */

[CCode (cheader_filename="r_parse.h", cprefix="r_parse_", lower_case_cprefix="r_parse_")]
namespace Radare {
	[Compact]
	[CCode (cname="RParse", free_function="r_parse_free", cprefix="r_parse_")]
	public class RParse {
		public RParse();

		public bool use(string name);
		public bool filter(uint64 addr, RFlag flag, RAnal.Hint hint, ref string data, ref string str, int len, bool bigendian);
		public bool assemble(ref string dst, ref string src);
		public bool parse(string dst, ref string src);
/*

		public void set_user_ptr(void *user);
		//TODO public bool @add();
		// This is the destructor
		public void free();
*/
		/* CParse api */
		// public static string c_file (RAnal anal, string path);
		// public static string c_string (RAnal anal, string str);
		// public static bool is_c_file (string path);
	}
}
