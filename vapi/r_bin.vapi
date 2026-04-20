/* radare - LGPL - Copyright 2009-2026 - pancake */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="RBinFileOptions", free_function="", cprefix="r_bin_", destroy_function="")]
	public struct RBinFileOptions {
		string pluginname;
		uint64 baseaddr; // where the linker maps the binary in memory
		uint64 loadaddr; // starting physical address to read from the target file
		uint64 sz;
		int xtr_idx; // load Nth binary
		int rawstr;
		int fd;
		string filename;
	}

	[Compact]
	[CCode (cname="RBinArchOptions", free_function="", cprefix="")]
	public class RBinArchOptions {
		string *arch;
		int bits;
	}

	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="RBinName", free_function="", cprefix="r_bin_name_", destroy_function="")]
	public class RBinName {
		public string name;
		public string oname;
		public string fname;
	}

	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="RBin", free_function="r_bin_free", cprefix="r_bin_",destroy_function="")]
	public class RBin {
		[CCode (cprefix="R_BIN_SYM_")]
		public enum Sym {
			ENTRY,
			INIT,
			MAIN,
			FINI,
			LAST
		}
		public unowned string file;
		public RBin.File cur;
		public int narch;

		public RBin();
		public RIO.Bind iob;

		public uint64 wr_scn_resize (string name, uint64 size);
		public int wr_rpath_del ();
		public int wr_output (string filename);

		public int open(string file, ref RBinFileOptions opts);
		public int use_arch(string arch, int bits, string name);
		public int select(string arch, int bits, string name);
		public uint64 get_baddr();
		public RBin.Addr get_sym(int sym);
		//public unowned RList<unowned RBin.Addr> get_entries();
		public unowned RList<unowned RBin.Section> get_sections();
		public unowned RList<unowned RBin.String> get_strings();
		public unowned RList<unowned RBin.Symbol> get_symbols();
		public unowned RList<unowned string> get_libs();
		public unowned RBin.Info get_info();

		[Compact]
		[CCode (cname="RBinFile", free_function="", ref_function="", unref_function="")]
		public class File {
			RBuffer buf;
			public unowned string file;
			public int size;
			public uint64 offset;
			public RBin.Object bo;
		}

		[CCode (cname="RBinPlugin", free_function="", ref_function="", unref_function="")]
		public class Plugin {
		}

		[CCode (cname="RBinClass", free_function="", ref_function="", unref_function="")]
		public class Class {
			public RBinName name;
			public int index;
			public RList<Symbol> methods;
			public RList<Field> fields;
		}

		[CCode (cname="RBinObject", free_function="", ref_function="", unref_function="")]
		public class Object {
			public uint64 baddr;
			public int size;
			public RList<RBin.Section> sections;
			public RList<RBin.Import> imports;
			public RList<RBin.Symbol> symbols;
			public RList<RBin.Addr> entries;
			public RList<RBin.Symbol> libs;
			public RList<RBin.String> strings;
			public RList<RBin.Class> classes;
			public RBin.Info info;
			public RBin.Addr binsym[4];
		}

		[CCode (cname="RBinAddr", free_function="", ref_function="", unref_function="")]
		public class Addr {
			public uint64 vaddr;
			public uint64 paddr;
		}

		[CCode (cname="RBinSection", free_function="", ref_function="", unref_function="")]
		public class Section {
			public string name;
			public uint64 size;
			public uint64 vsize;
			public uint64 vaddr;
			public uint64 paddr;
			public uint32 perm;
		}

		[CCode (cname="RBinSymbol", free_function="", ref_function="", unref_function="")]
		public class Symbol {
			public RBinName name;
			public string forwarder;
			public string bind;
			public string type;
			public string classname;
			public uint64 vaddr;
			public uint64 paddr;
			public uint32 size;
			public uint32 ordinal;
		}

		[CCode (cname="RBinImport", free_function="", ref_function="", unref_function="")]
		public class Import {
			public RBinName name;
			public string bind;
			public string type;
			public string classname;
			public string descriptor;
			public uint32 ordinal;
		}


		[CCode (cprefix="R_BIN_RELOC")]
		public enum RelocType {
			_8,
			_16,
			_32,
			_64
		}
		[CCode (cname="RBinReloc", free_function="", ref_function="", unref_function="")]
		public class Reloc {
			public uint8 type;
			public uint8 additive;
			public RBin.Symbol symbol;
			public RBin.Import import;
			public int64 addend;
			public uint64 vaddr;
			public uint64 paddr;
			public uint32 visibility;
		}

		[CCode (cname="RBinInfo", free_function="", ref_function="", unref_function="")]
		public class Info {
			public string? file;
			public string? type;
			public string? bclass;
			public string? rclass;
			public string? arch;
			public string? machine;
			public string? os;
			public string? subsystem;
			public string? rpath;
			public unowned string lang;
			public int bits;
			public bool has_va;
			public bool has_pi;
			public int big_endian;
			public uint64 dbg_info;
		}

		[Compact]
		[CCode (cname="RBinString", free_function="", ref_function="", unref_function="")]
		public class String {
			public string @string;
			public uint64 vaddr;
			public uint64 paddr;
			public uint64 ordinal;
			public uint64 size;
		}

		[Compact]
		[CCode (cname="RBinField", free_function="", ref_function="", unref_function="")]
		public class Field {
			public RBinName name;
			public uint64 vaddr;
			public uint64 paddr;
		}
	}
}
