/* radare - LGPL - Copyright 2010-2026 pancake<@nopcode.org> */

[CCode (cheader_filename="r_flag.h,r_list.h,r_types_base.h", cprefix="r_flag_", lower_case_cprefix="r_flag_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_flag_item_", cname="RFlagItem", free_function="")]
	public class RFlagItem {
		public string name;
		public uint64 size;
		public uint64 addr;
	}

	[Compact]
	[CCode (cname="RFlag", free_function="r_flag_free", cprefix="r_flag_")]
	public class RFlag {
		public RFlag();
		public void list(bool rad, string? pfx = null);
		public RFlagItem get(string name);
		public RFlagItem get_in(uint64 addr);
		public bool unset_name(string name);
		public bool unset_addr(uint64 addr);
		public RFlagItem set(string name, uint64 addr, int size=1);

		public void space_set(string name);
	}
}
