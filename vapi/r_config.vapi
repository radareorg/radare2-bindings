[CCode (cheader_filename="r_config.h", cprefix="r_", lower_case_cprefix="r_")]
namespace Radare {
	/**
	 * Radare2 Configuration Module
	 */
	[Compact]
	[CCode (cprefix="r_config_", cname="RConfig", free_function="r_config_free")]
	public class RConfig {
		public RConfig (void* user = null);
		public RConfig clone();
		public void serialize(SDB.Sdb db);
		public bool unserialize(SDB.Sdb db, out string err);

		public void lock (bool enable);
		public void bump (string key);
		public bool eval(string str, bool many);
		/**
		 * Make the specific key read only, can't be modified
		 */
		public bool readonly(string key);

		public unowned string get(string name);
		public uint64 get_i(string name);

		public unowned RConfigNode node_get (string name);
		public static RConfigNode node_new (string name, string val);

		public unowned string desc (string name, string? desc);
		public int toggle (string name);
		public unowned RConfigNode set(string name, string val);
		public unowned RConfigNode set_i(string name, uint64 val);

		public void list(string? foo, bool rad);
	}

	[Compact]
	[CCode (cname="RConfigNode", cprefix="r_config_node_", free_function="r_config_node_free", unref_function="")]
	public class RConfigNode {
		string name;
		int hash;
		uint32 flags;
		string @value;
		uint64 i_value;

		/* TODO: moar */
		public string to_string();
		public void add_option(string option);
		public void purge_options();
	}

	[CCode (cname="int", cprefix="CN_")]
	public enum RConfigNodeType {
		BOOL,
		INT,
		OFFT,
		STR,
		RO,
		RW,
	}
}
