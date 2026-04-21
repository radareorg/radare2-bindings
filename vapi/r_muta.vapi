/* radare - LGPL - Copyright 2026 - pancake */

namespace Radare {
	[CCode (cname="int", cprefix="R_MUTA_OP_")]
	public enum MutaOp {
		NONE,
		HASH,
		DECRYPT,
		ENCRYPT
	}

	[CCode (cname="int", cprefix="R_MUTA_TYPE_", cheader_filename="r_muta.h")]
	public enum MutaType {
		HASH,
		BASE,
		CRYPTO,
		SIGN,
		CHARSET,
		ALL
	}

	[SimpleType]
	[CCode (cheader_filename="r_muta.h", cname="RMutaResult", destroy_function="")]
	public struct RMutaResult {
		public uint8 *output;
		public int output_len;
		public int output_size;
		public double entropy;
		public string hex;
		public bool success;
		public bool text_output;
	}

	[Compact]
	[CCode (cheader_filename="r_muta.h", cname="RMutaSession", cprefix="r_muta_session_", free_function="r_muta_session_free")]
	public class RMutaSession {
		public int key_len;
		public int dir;

		public bool set_key(uint8 *key, int keylen, int mode, int direction);
		public bool set_iv(uint8 *iv, int ivlen);
		public bool set_subtype(string subtype);

		public bool update(uint8 *buf, int len);
		public bool end(uint8 *buf, int len);
		public int append(uint8 *buf, int len);
		public uint8 *get_output(out int size);
	}

	[Compact]
	[CCode (cheader_filename="r_muta.h", cname="RMuta", cprefix="r_muta_", free_function="r_muta_free")]
	public class RMuta {
		public bool bigendian;

		public RMuta();

		/**
		 * List available muta plugins of the given type
		 */
		public string list(MutaType type, int mode);

		/**
		 * Query the type of the named algorithm (hash, crypto, ...)
		 */
		public MutaType algo_type(string algo);

		/**
		 * Check whether the named algorithm supports the requested type
		 */
		public bool algo_supports(string algo, MutaType type);

		/**
		 * Create a new muta session for the given algorithm
		 */
		public RMutaSession use(string algo);

		/**
		 * One-shot hash / entropy computation. The result struct owns heap
		 * allocations; free with r_muta_result_free when done.
		 */
		public RMutaResult process_simple(string algo, uint8 *data, int len);

		/**
		 * Unified one-shot processing for hash/crypto/charset/etc
		 */
		public RMutaResult process(string algo, uint8 *data, int len,
			uint8 *key, int key_len, uint8 *iv, int iv_len, int direction);
	}

	[CCode (cheader_filename="r_muta.h", cname="r_muta_result_free")]
	public void muta_result_free(ref RMutaResult res);
}
