/* radare - LGPL - Copyright 2009-2026 - pancake */

namespace Radare {
	[CCode (cheader_filename="r_cons.h", cname="RCons", free_function="r_cons_free", unref_function="", cprefix="r_cons_")]
	public class RCons {
		public RCons ();
		public static RCons singleton ();

		[CCode (cname="Color_RED")]
		public const string RED;
		[CCode (cname="Color_BLACK")]
		public const string BLACK;
		[CCode (cname="Color_WHITE")]
		public const string WHITE;
		[CCode (cname="Color_RESET")]
		public const string RESET;
		[CCode (cname="Color_MAGENTA")]
		public const string MAGENTA;
		[CCode (cname="Color_YELLOW")]
		public const string YELLOW;
		[CCode (cname="Color_TURQOISE")]
		public const string TURQOISE;
		[CCode (cname="Color_BLUE")]
		public const string BLUE;
		[CCode (cname="Color_GRAY")]
		public const string GRAY;

		public int pipe_open (string file, int fdn, int append);
		public void pipe_close (int fd);

		public void clear();
		public void clear00();
		public void reset();
		public void gotoxy(int x, int y);
		public void set_raw(bool is_raw);

		public void print(string str);
		public void newline();
		public void filter();
		public void visual_flush();
		public void flush();

		public int readchar();
		public int any_key(string? msg=null);
		public int get_size(out int rows);

		public int arrow_to_hjkl (int ch);
		public void invert (int set, int color);
	}
	[Compact]
	[CCode (cname="RLine", cheader_filename="r_cons.h", cprefix="r_line_", free_function="")]
	public class RLine {
		public bool hist_load (string file);
		public bool hist_add (string text);
		public bool hist_save (string file);
	}
}
