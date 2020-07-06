/* radare - LGPL - Copyright 2009-2015 - pancake */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="RBinOptions", free_function="", cprefix="r_bin_")]
	public class RBinOptions {
		int rawstr;
		uint64 baddr;
		uint64 laddr;
		uint64 paddr;
		string plugname;
	}
	
	[Compact]
	[CCode (cname="RBinArchOptions", free_function="", cprefix="")]
	public class RBinArchOptions {
		string *arch;
		int bits;
	}

	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="RBin", free_function="r_bin_free", cprefix="r_bin_")]
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
		// public void iobind (RIO io);

		public uint64 wr_scn_resize (string name, uint64 size);
		public int wr_rpath_del ();
		public int wr_output (string filename);

		public int open(string file, RBinOptions opts);
		public RBuffer create(string plugin_name,uint8 *code, int codelen, uint8 *data, int datalen, RBinArchOptions *opt);
		public int use_arch(string arch, int bits, string name);
		public int select(string arch, int bits, string name);
		// public int select_idx(string? name, int idx);
		// public void list(int mode);
		public uint64 get_baddr();
		public RBin.Addr get_sym(int sym); // XXX: use RBin.Sym here ?
		public unowned RList<unowned RBin.Addr> get_entries();
		public unowned RList<unowned RBin.Field> get_fields();
		public unowned RList<unowned RBin.Import> get_imports();
		public unowned RList<unowned RBin.Section> get_sections();
		public unowned RList<unowned RBin.String> get_strings();
		public unowned RList<unowned RBin.Symbol> get_symbols();
		// public unowned RList<unowned RBin.Reloc> get_relocs();
		public unowned RList<unowned string> get_libs();
		public unowned RBin.Info get_info();
		public int addr2line(uint64 addr, ref string file, int len, out int line);
		public string addr2text(uint64 addr, bool origin);

		[Compact]
		[CCode (cname="RBinFile", free_function="", ref_function="", unref_function="")]
		public class File {
			RBuffer buf;
			public unowned string file;
			public int size;
			public uint64 offset;
			public RBin.Object o;
			// public Plugin curplugin;
		}

		[CCode (cname="RBinPlugin", free_function="", ref_function="", unref_function="")]
		public class Plugin {
		}

		[CCode (cname="RBinDwarfRow", free_function="", ref_function="", unref_function="")]
		public class DwarfRow {
			public uint64 address;
			public string file;
			public int line;
			public int column;
		}

		[CCode (cname="RBinClass", free_function="", ref_function="", unref_function="")]
		public class Class {
			public string name;
			public string super;
			public int index;
			public RList<Symbol> methods;
			public RList<Field> fields;
			public bool visibility;
		}

		[CCode (cname="RBinObject", free_function="", ref_function="", unref_function="")]
		public class Object {
			public uint64 baddr;
			public int size;
			public RList<RBin.Section> sections;
			public RList<RBin.Import> imports;
			public RList<RBin.Symbol> symbols;
			//public RList<RBin.Symbol> entries;
			public RList<RBin.Addr> entries;
			public RList<RBin.Field> fields;
			public RList<RBin.Symbol> libs;
			// public RList<RBin.Reloc> relocs;
			public RList<RBin.String> strings;
			public RList<RBin.Class> classes;
			public RList<RBin.DwarfRow> lines;
			public RBin.Info info;
			public RBin.Addr binsym[4]; //
		}

		[CCode (cname="RBinAddr", free_function="", ref_function="", unref_function="")]
		public class Addr {
			public uint64 vaddr;
			public uint64 paddr;
		}

		[CCode (cname="RBinSection", free_function="", ref_function="", unref_function="")]
		public class Section {
			public char name[512]; // FIXME proper static strings w/o hardcoded size
			public uint64 size;
			public uint64 vsize;
			public uint64 vaddr;
			public uint64 paddr;
			public uint64 perm;
		}

		[CCode (cname="RBinSymbol", free_function="", ref_function="", unref_function="")]
		public class Symbol {
			public string name; // FIXME proper static strings w/o hardcoded size
			public string forwarder; // FIXME proper static strings w/o hardcoded size
			public string bind; // FIXME proper static strings w/o hardcoded size
			public string type; // FIXME proper static strings w/o hardcoded size
			public string classname; // FIXME proper static strings w/o hardcoded size
			public uint64 vaddr;
			public uint64 paddr;
			public uint64 size;
			public uint64 ordinal;
		}

		[CCode (cname="RBinImport", free_function="", ref_function="", unref_function="")]
		public class Import {
			public string name; // FIXME proper static strings w/o hardcoded size
			public string bind; // FIXME proper static strings w/o hardcoded size
			public string type; // FIXME proper static strings w/o hardcoded size
			public string classname; // FIXME proper static strings w/o hardcoded size
			public string descriptor; // FIXME proper static strings w/o hardcoded size
			public uint64 ordinal;
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
			public string? file; // FIXME proper static strings w/o hardcoded size
			public string? type; // FIXME proper static strings w/o hardcoded size
			public string? bclass; // FIXME proper static strings w/o hardcoded size
			public string? rclass; // FIXME proper static strings w/o hardcoded size
			public string? arch; // FIXME proper static strings w/o hardcoded size
			public string? machine; // FIXME proper static strings w/o hardcoded size
			public string? os; // FIXME proper static strings w/o hardcoded size
			public string? subsystem; // FIXME proper static strings w/o hardcoded size
			public string? rpath; // FIXME proper static strings w/o hardcoded size
			public unowned string lang;
			public int bits;
			public bool has_va;
			public bool has_pi;
			public bool big_endian;
			public uint64 dbg_info;
		}

		[CCode (cname="RBinString", free_function="", ref_function="", unref_function="")]
		public class String {
			public string @string; // FIXME proper static strings w/o hardcoded size
			public uint64 vaddr;
			public uint64 paddr;
			public uint64 ordinal;
			public uint64 size;
		}

		[CCode (cname="RBinField", free_function="", ref_function="", unref_function="")]
		public class Field {
			public string name; // FIXME proper static strings w/o hardcoded size
			public uint64 vaddr;
			public uint64 paddr;
		}
	}
}
