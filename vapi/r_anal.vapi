/* radare - LGPL - Copyright 2010-2018 - pancake */

/* this vapi is broken as shit... we need to rename some stuff here ..
   if we can just avoid to use cname CCode attribute... */

namespace Radare {

	[Compact]
	[CCode (cheader_filename="r_anal.h,r_list.h,r_types_base.h", cprefix="r_anal_", lowercase_c_prefix="r_anal_", free_function="r_anal_free", cname="RAnal")]
	public class RAnal {
		public int bits;
		public bool big_endian;
		public void *user;
		public RList<Function> fcns;
//		public RList<VarType> vartypes;
//		public RList<MetaItem> meta;
		public RList<Refline> reflines;
		public RReg reg;
		public RSyscall syscall;

		/* bindiffing options
		-- THIS IS PRIVATE --
		public bool diff_ops;
		public double diff_thbb;
		*/

		public RAnal ();
		public bool op_hexstr(uint64 addr, string hexstr);
		//public bool esil_eval (string str);
		public bool set_bits (int bits);
		public bool set_big_endian (bool big);
		//public bool set_pc (uint64 addr);
		public void diff_setup(bool doops, double thbb, double thfcn);
		public void diff_setup_i(bool doops, int thbb, int thfcn);

		public RList<RAnal.Ref> xrefs_get (uint64 addr);
		public RList<RAnal.Ref> xrefs_get_from (uint64 addr);
		//public RList<RAnal.Ref> xrefs_from(uint64 addr);

		public unowned RList<unowned RAnal.Function> get_fcns();
		// public Function get_fcn_at (uint64 addr, int type);
		// public Function get_fcn_in (uint64 addr, int type);
		public void trace_bb (uint64 addr);

		[Compact]
		[CCode (cprefix="r_anal_case_", free_function="free", cname="RAnalCaseOp")]
		public class CaseOp {
			public uint64 addr;
			public uint64 jump;
			public uint64 value;
			// public uint32 cond;
			// public uint64 bb_ref_to;
			// public uint64 bb_ref_from;
		}

/*
		[Compact]
		[CCode (cprefix="r_anal_switch_op_", free_function="r_anal_switch_op_free", cname="RAnalSwitchOp")]
		public class SwitchOp {
			public uint64 addr;
			public uint64 min_val;
			public uint64 def_val;
			public uint32 max_val;
			public RList<RAnal.CaseOp> cases;

			public SwitchOp(uint64 addr, uint64 min_val, uint64 max_val);
			public CaseOp add_case(uint64 addr, uint64 jump, uint64 value);
		}

*/
		[Compact]
		[CCode (cname="RAnalValue")]
		public class Value {
			public bool absolute;
			public bool memref;
			public uint64 @base;
			public int64 delta;
			public int64 imm;
			public int mul;
			//public uint16 sel;
			public RReg.Item reg;
			public RReg.Item regdelta;
		}

		[Compact]
		[CCode (cname="RAnalCond")]
		public class Cond {
			public int type;
			public Value arg[2];
		}

		[Compact]
		[CCode (cname="RAnalHint")]
		public class Hint {
			public uint64 addr;
			public uint64 ptr;
			public uint64 jump;
			public string arch;
			public string opcode;
		}

		[CCode (cname="int", cprefix="R_ANAL_FCN_TYPE_")]
		public enum FcnType {
			FCN,
			LOC,
			SYM,
			IMP,
			ROOT
		}

		[CCode (cname="int", cprefix="R_ANAL_COND_")]
		public enum Cnd {
			EQ,
			NE,
			GE,
			GT,
			LE,
			LT,
			AL,
			NV
		}

/*
		[Compact]
		//[CCode (cprefix="r_anal_state_", cname="RAnalState")]
		[CCode (cprefix="r_anal_state_", free_function="r_anal_state_free", cname="RAnalState")]
		public class State {
			public uint64 start;
			public uint64 end;
			public uint8 *buffer;
			public uint64 len;

			public uint64 bytes_consumed;
			public uint64 last_addr;
			public uint64 current_addr;
			public uint64 next_addr;

			public RList<RAnal.Block> bbs;
			//public RHashTable64 ht;
			public uint64 ht_sz;

			public Function current_fcn;
			public Op current_op;
			public Block current_bb;
			public Block current_bb_head;

			public uint8 done;
			public int anal_ret_val;
			public uint32 current_depth;
			public uint32 max_depth;

			public void *user_state;

			public State(uint64 start, uint8 * buffer, uint64 len);
			public void insert_bb (RAnal.Block *bb);
			//public int need_rehash (RAnal.Block *bb);
			public Block search_bb (uint64 addr);
			public uint64 get_len (uint64 addr);
			//public uint8* get_buf_by_addr (uint64 addr);
			// public int addr_is_valid (uint64 addr);
			//public void merge_bb_list (RList<RAnal.Block> bbs);
			// public void set_depth(uint32 depth);
		}
*/

/*
		[CCode (cname="int", cprefix="R_ANAL_VAR_TYPE_")]
		public enum VarClass {
			NULL,
			GLOBAL,
			LOCAL,
			ARG,
			ARGREG
		}
*/

		[CCode (cname="int", cprefix="R_ANAL_FCN_TYPE_")]
		public enum FunctionType {
			NULL,
			FCN,
			LOC,
			SYM,
			IMP
		}

		[CCode (cname="int", cprefix="R_ANAL_BB_TYPE_")]
		public enum BlockType {
			NULL,
			HEAD,
			BODY,
			LAST,
			FOOT,
			SWITCH,
			RET,
			JMP,
			COND,
			CALL,
			CMP,
			LD,
			ST,
			BINOP,
			TAIL
		}

		[CCode (cname="int", cprefix="R_ANAL_DIFF_TYPE_")]
		public enum BlockDiff {
			NULL,
			MATCH,
			UNMATCH
		}

		[CCode (cname="int", cprefix="R_ANAL_REFLINE_TYPE_")]
		public enum ReflineType {
			STYLE,
			WIDE
		}

		[CCode (cname="int", cprefix="R_ANAL_RET_")]
		public enum Ret {
			ERROR,
			DUP,
			NEW,
			END
		}

		[CCode (cname="int", cprefix="R_ANAL_STACK_")]
		public enum Stack {
			NULL,
			NOP,
			INC,
			GET,
			SET
		}

		[CCode (cname="int", cprefix="R_ANAL_DATA_")]
		public enum Data {
			NULL,
			HEX,
			STR,
			CODE,
			FUN,
			STRUCT,
			LAST
		}

		[CCode (cname="int", cprefix="R_ANAL_OP_FAMILY_")]
		public enum OpFamily {
			UNKNOWN,
			CPU,
			FPU,
			MMX,
			PRIV,
			LAST
		}

		[CCode (cname="int", cprefix="R_ANAL_VAR_DIR_")]
		public enum VarDir {
			NONE,
			IN,
			OUT
		}

		[CCode (cname="int", cprefix="R_ANAL_OP_TYPE_")]
		public enum OpType {
			NULL,
			JMP,
			UJMP,
			CJMP,
			CALL,
			UCALL,
			REP,
			RET,
			ILL,
			UNK,
			NOP,
			MOV,
			TRAP,
			SWI,
			UPUSH,
			PUSH,
			POP,
			CMP,
			ADD,
			SUB,
			MUL,
			DIV,
			SHR,
			SHL,
			OR,
			AND,
			XOR,
			NOT,
			STORE,
			LOAD,
			LEA,
			LEAVE,
			ROR,
			ROL,
			XCHG,
			MOD,
			SWITCH,
			//LAST
		}

		[Compact]
		[CCode (cprefix="r_anal_bb_", cname="RAnalBlock", free_function="")]
		public class Block {
			// public char* name;
			public uint64 addr;
			public uint64 jump;
			// public uint64 type2;
			public uint64 fail;
			// public int size;
			// public BlockType type;
			// public BlockType type_ex;
			public int ninstr;
			// public bool returnbb;
			// public bool conditional;
			public bool traced;
			// public char* label;
			public uint8 * fingerprint;
			public Diff diff;
			// public Cond cond;
			// public SwitchOp switch_op;
			public uint8 op_bytes[30];
			// public uint8 op_sz;
/*
#if VALABIND_CTYPES
			public void* head;
			// public void* tail;
			public void* next;
			public void* prev;
			public void* failbb;
			public void* jumpbb;
#else
			public Block head;
			// public Block tail;
			public Block next;
			public Block prev;
			public Block failbb;
			public Block jumpbb;
#endif
*/
			//public RList<RAnal.Op> ops;
		}

		// public void bb (Block bb, uint64 addr, uint8 *buf, uint64 len, bool head);
		// public Block bb_from_offset (uint64 addr);

		[Compact]
		[CCode (cprefix="r_anal_op_", cname="RAnalOp")]
		public class Op {
			public string mnemonic;
			public uint64 addr;
			public int type;
			// public bool stackop;
			// public int cond;
			public int size;
			public int nopcode;
			// public int family;
			public bool eob;
			public int delay;
			public uint64 jump;
			public uint64 fail;
			public int64 ptr;
			public uint64 val;
			public int64 stackptr;
			public bool refptr;
			public Value src[3];
			public Value dst;
			// SWIG FAIL // public RStrBuf esil;
			//TODO public uint64 ref;
		}

/*
		public string op_to_string(Op op);
		public unowned string op_to_esil_string(Op op);
*/

		[Compact]
		[CCode (cprefix="r_anal_diff_", cname="RAnalDiff")]
		public class Diff {
			public BlockDiff type;
			public string name;
			public uint64 addr;
		}

		[CCode (cname="RAnalFunction", free_function="", cprefix="r_anal_fcn_", ref_function="", unref_function="", free_function="")]
		public class Function {
			public string name;
			// public string dsc;
			// public int _size;
			public int bits;
			// public short type;
			// public string rets;
			// public short fmod;
			public string cc;
			// public string attr;

			public uint64 addr;
			public int stack;
			public int maxstack;
			public int ninstr;
			// public int nargs;
			// public int depth;
			public bool folded;
			//public Type args;
			// MUST BE deprecated public VarSub varsubs[32];

			public Diff diff;
			public uint8 * fingerprint;
			//public FunctionType type;
			// public RList<RAnal.Block> bbs;
			// public RList<RAnal.Block> get_bbs();
			// public RList<RAnal.Var> vars;
			// public RList<RAnal.Var> get_vars();
			//public RList<RAnal.Ref> get_refs();
			// public RList<RAnal.Ref> get_xrefs();
		}

		[Compact]
		[CCode (cname="RAnalVar", free_function="")]
		public class Var {
			public string name;
			public string type;
			public int delta;
		}


#if 0
		[Compact]
		[CCode (cname="RAnalVarSub")]
		public struct VarSub {
			public char pat[1024];
			public char sub[1024];
		}

		[Compact]
		[CCode (cname="RAnalType")]
		public class Type {
			public string name;
			public uint32 size;
			public int type;
			// TODO. add custom union type here
		}
#endif
/*
		[Compact]
		[CCode (cname="RAnalVarType")]
		public class VarType {
			public string name;
			public string fmt;
			public uint size;
		}
*/

		[Compact]
		[CCode (cname="RAnalRef", free_function="")]
		public class Ref {
			public uint64 addr;
			public uint64 at;
		}

		[Compact]
		[CCode (cname="RAnalRefline", free_function="")]
		public class Refline {
			public uint64 from;
			public uint64 to;
			public int index;
		}

	/* meta */
	[Compact]
	[CCode (cname="RAnalMetaItem",cprefix="r_anal_meta_item_", free_function="")] // r_meta_item_free")]
	public class MetaItem {
/*
		public uint64 from;
		public uint64 to;
		public uint64 size;
		public int type;
		public string str;
*/
	}

	[CCode (cname="int", cprefix="R_META_WHERE_")]
	public enum MetaWhere {
		PREV,
		HERE,
		NEXT
	}

	[CCode (cname="int", cprefix="R_META_TYPE_")]
	public enum MetaType {
		ANY,
		DATA,
		CODE,
		STRING,
		COMMENT
	}

	//public int count (MetaType type, uint64 from, uint64 to,
	//public string get_string(MetaType, uint64 addr);
	//[CCode (cname="r_meta_add")]
	// public bool meta_add(MetaType type, uint64 from, uint64 size, string str);
	//[CCode (cname="r_meta_del")]
	//public bool meta_del(MetaType type, uint64 from, uint64 size, string str);
/*
	[CCode (cname="r_meta_find")]
	public MetaItem meta_find(uint64 off, MetaType type, MetaWhere where);
	[CCode (cname="r_meta_cleanup")]
	public bool meta_cleanup (uint64 from, uint64 to);
	[CCode (cname="r_meta_type_to_string")]
	public static unowned string meta_type_to_string(MetaType type);
	[CCode (cname="r_meta_list")]
	public int meta_list(MetaType type, uint64 rad);
*/
	}

/*
	[Compact]
	[CCode (cheader_filename="r_sign.h", cprefix="r_sign_", lower_case_cprefix="r_sign_", cname="RSign", free_function="r_sign_free")]
	public class RSign {
		public RSign ();
	}
*/

	/* r_anal_ex.h */
	[CCode (cname="uint64", cprefix="R_ANAL_EX_")]
	public enum ExOpType {
		ILL_OP,
		NULL_OP,
		NOP,
		STORE_OP,
		LOAD_OP,
		REG_OP,
		OBJ_OP,
		STACK_OP,
		BIN_OP,
		CODE_OP,
		DATA_OP,
		UNK_OP,
		REP_OP,
		COND_OP,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_TYPE_")]
	public enum ExDataType {
		REF_NULL,
		REF_UNK,
		REF,
		SIGNED,
		PRIM,
		CONST,
		STATIC,
		VOLATILE,
		PUBLIC,
		BOOL,
		BYTE,
		SHORT,
		INT32,
		INT64,
		FLOAT,
		DOUBLE,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_CODEOP_")]
	public enum ExCodeOp {
		JMP,
		CALL,
		RET,
		TRAP,
		SWI,
		IO,
		LEAVE,
		SWITCH,
		CJMP,
		EOB,
		UCALL,
		UJMP,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_BINOP_")]
	public enum ExBinOp {
		XCHG,
		CMP,
		ADD,
		SUB,
		MUL,
		DIV,
		SHR,
		SHL,
		SAL,
		SAR,
		OR,
		AND,
		XOR,
		NOT,
		MOD,
		ROR,
		ROL,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_OBJOP_")]
	public enum ExObjOp {
		CAST,
		CHECK,
		NEW,
		DEL,
		SIZE,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_LDST_")]
	public enum ExLdStOp {
		FROM_REF,
		FROM_MEM,
		FROM_REG,
		FROM_STACK,
		FROM_CONST,
		FROM_VAR,
		INDIRECT_REF,
		INDIRECT_MEM,
		INDIRECT_REG,
		INDIRECT_STACK,
		INDIRECT_IDX,
		INDIRECT_VAR,
		TO_REF,
		TO_MEM,
		TO_REG,
		TO_STACK,
		TO_VAR,
		OP_PUSH,
		OP_POP,
		OP_MOV,
		OP_EFF_ADDR,
		OP_UPOP,
		OP_UPUSH,
		LOAD_FROM_CONST_REF_TO_STACK,
		LOAD_FROM_CONST_TO_STACK,
		LOAD_FROM_CONST_INDIRECT_TO_STACK,
		LOAD_FROM_VAR_INDIRECT_TO_STACK,
		LOAD_FROM_VAR_INDIRECT_TO_STACK_REF,
		LOAD_FROM_VAR_TO_STACK,
		LOAD_FROM_VAR_TO_STACK_REF,
		LOAD_FROM_REF_INDIRECT_TO_STACK,
		LOAD_FROM_REF_INDIRECT_TO_STACK_REF,
		STORE_FROM_STACK_INDIRECT_TO_VAR,
		STORE_FROM_STACK_INDIRECT_TO_VAR_REF,
		STORE_FROM_STACK_TO_VAR,
		STORE_FROM_STACK_TO_VAR_REF,
		STORE_FROM_STACK_INDIRECT_TO_REF,
		STORE_FROM_STACK_INDIRECT_TO_REF_REF,
		LOAD_FROM_REF_TO_STACK,
		LOAD_FROM_PRIM_VAR_TO_STACK,
		LOAD_GET_STATIC,
		STORE_PUT_STATIC,
		LOAD_GET_FIELD,
		STORE_PUT_FIELD,
	}

	[CCode (cname="uint64", cprefix="R_ANAL_EX_FMT_")]
	public enum ExFmt {
		EXEC,
		DATA,
		MIXED,
	}

	// public static uint64 ex_map_anal_ex_to_anal_op_type(uint64 ranal2_op_type);
	// public static int ex_is_op_type_eop(uint64 x);
	// public static uint32 ex_map_anal_ex_to_anal_bb_type (uint64 ranal2_op_type);
	// public static void ex_clone_op_switch_to_bb (RAnal.Block *bb, RAnal.Op *op);
	// public static void ex_update_bb_cfg_head_tail( RAnal.Block start, RAnal.Block head, RAnal.Block tail );

	// public static int ex_bb_head_comparator(RAnal.Block a, RAnal.Block b);
	// public static int ex_bb_address_comparator(RAnal.Block a, RAnal.Block b);


//	public RList<RAnal.Block> ex_analyze( RAnal.State state, uint64 addr);
//	public RList<RAnal.Block> ex_analysis_driver( RAnal.State state, uint64 addr);
//	public void ex_op_to_bb(RAnal.State state, RAnal.Block bb, RAnal.Op op);
//	public RAnal.Op ex_get_op(RAnal.State state, uint64 addr);
//	public RAnal.Block ex_get_bb(RAnal.State state, uint64 addr);

}
