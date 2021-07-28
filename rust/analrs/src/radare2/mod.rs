use libc::*;
use std::ffi::CStr;
use std::ffi::CString;

pub const R_ANAL_OP_TYPE_COND: u32 = 0x80000000;
pub const R_ANAL_OP_TYPE_REP: u32 = 0x40000000;
pub const R_ANAL_OP_TYPE_MEM: u32 = 0x20000000; // TODO must be moved to prefix?
pub const R_ANAL_OP_TYPE_REG: u32 = 0x10000000; // operand is a register
pub const R_ANAL_OP_TYPE_IND: u32 = 0x08000000; // operand is indirect
pub const R_ANAL_OP_TYPE_NULL: u32 = 0;
pub const R_ANAL_OP_TYPE_JMP: u32 = 1; /* mandatory jump */
pub const R_ANAL_OP_TYPE_UJMP: u32 = 2; /* unknown jump (register or so) */
pub const R_ANAL_OP_TYPE_RJMP: u32 = R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP;
pub const R_ANAL_OP_TYPE_IJMP: u32 = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UJMP;
pub const R_ANAL_OP_TYPE_IRJMP: u32 = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP;
pub const R_ANAL_OP_TYPE_CJMP: u32 = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP; /* conditional jump */
pub const R_ANAL_OP_TYPE_MJMP: u32 = R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_JMP; /* conditional jump */
pub const R_ANAL_OP_TYPE_UCJMP: u32 = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP; /* conditional unknown jump */
pub const R_ANAL_OP_TYPE_CALL: u32 = 3; /* call to subroutine (branch+link) */
pub const R_ANAL_OP_TYPE_UCALL: u32 = 4; /* unknown call (register or so) */
pub const R_ANAL_OP_TYPE_RCALL: u32 = R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL;
pub const R_ANAL_OP_TYPE_ICALL: u32 = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UCALL;
pub const R_ANAL_OP_TYPE_IRCALL: u32 =
    R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL;
pub const R_ANAL_OP_TYPE_CCALL: u32 = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL; /* conditional call to subroutine */
pub const R_ANAL_OP_TYPE_UCCALL: u32 = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL; /* conditional unknown call */
pub const R_ANAL_OP_TYPE_RET: u32 = 5; /* returns from subroutine */
pub const R_ANAL_OP_TYPE_CRET: u32 = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET; /* conditional return from subroutine */
pub const R_ANAL_OP_TYPE_ILL: u32 = 6; /* illegal instruction // trap */
pub const R_ANAL_OP_TYPE_UNK: u32 = 7; /* unknown opcode type */
pub const R_ANAL_OP_TYPE_NOP: u32 = 8; /* does nothing */
pub const R_ANAL_OP_TYPE_MOV: u32 = 9; /* register move */
pub const R_ANAL_OP_TYPE_CMOV: u32 = 9 | R_ANAL_OP_TYPE_COND; /* conditional move */
pub const R_ANAL_OP_TYPE_TRAP: u32 = 10; /* it's a trap! */
pub const R_ANAL_OP_TYPE_SWI: u32 = 11; /* syscall, software interrupt */
pub const R_ANAL_OP_TYPE_UPUSH: u32 = 12; /* unknown push of data into stack */
pub const R_ANAL_OP_TYPE_PUSH: u32 = 13; /* push value into stack */
pub const R_ANAL_OP_TYPE_POP: u32 = 14; /* pop value from stack to register */
pub const R_ANAL_OP_TYPE_CMP: u32 = 15; /* compare something */
pub const R_ANAL_OP_TYPE_ACMP: u32 = 16; /* compare via and */
pub const R_ANAL_OP_TYPE_ADD: u32 = 17;
pub const R_ANAL_OP_TYPE_SUB: u32 = 18;
pub const R_ANAL_OP_TYPE_IO: u32 = 19;
pub const R_ANAL_OP_TYPE_MUL: u32 = 20;
pub const R_ANAL_OP_TYPE_DIV: u32 = 21;
pub const R_ANAL_OP_TYPE_SHR: u32 = 22;
pub const R_ANAL_OP_TYPE_SHL: u32 = 23;
pub const R_ANAL_OP_TYPE_SAL: u32 = 24;
pub const R_ANAL_OP_TYPE_SAR: u32 = 25;
pub const R_ANAL_OP_TYPE_OR: u32 = 26;
pub const R_ANAL_OP_TYPE_AND: u32 = 27;
pub const R_ANAL_OP_TYPE_XOR: u32 = 28;
pub const R_ANAL_OP_TYPE_NOR: u32 = 29;
pub const R_ANAL_OP_TYPE_NOT: u32 = 30;
pub const R_ANAL_OP_TYPE_STORE: u32 = 31; /* store from register to memory */
pub const R_ANAL_OP_TYPE_LOAD: u32 = 32; /* load from memory to register */
pub const R_ANAL_OP_TYPE_LEA: u32 = 33; /* TODO add ulea */
pub const R_ANAL_OP_TYPE_LEAVE: u32 = 34;
pub const R_ANAL_OP_TYPE_ROR: u32 = 35;
pub const R_ANAL_OP_TYPE_ROL: u32 = 36;
pub const R_ANAL_OP_TYPE_XCHG: u32 = 37;
pub const R_ANAL_OP_TYPE_MOD: u32 = 38;
pub const R_ANAL_OP_TYPE_SWITCH: u32 = 39;
pub const R_ANAL_OP_TYPE_CASE: u32 = 40;
pub const R_ANAL_OP_TYPE_LENGTH: u32 = 41;
pub const R_ANAL_OP_TYPE_CAST: u32 = 42;
pub const R_ANAL_OP_TYPE_NEW: u32 = 43;
pub const R_ANAL_OP_TYPE_ABS: u32 = 44;
pub const R_ANAL_OP_TYPE_CPL: u32 = 45; /* complement */
pub const R_ANAL_OP_TYPE_CRYPTO: u32 = 46;
pub const R_ANAL_OP_TYPE_SYNC: u32 = 47;

#[repr(C)]
pub enum RLibType {
    RLibTypeIo = 0,
    RLibTypeDbg = 1,
    RLibTypeLang = 2,
    RLibTypeAsm = 3,
    RLibTypeAnal = 4,
    RLibTypeParse = 5,
    RLibTypeBin = 6,
    RLibTypeBinXtr = 7,
    RLibTypeBinLdr = 8,
    RLibTypeBp = 9,
    RLibTypeSyscall = 10,
    RLibTypeFastcall = 11,
    RLibTypeCrypto = 12,
    RLibTypeCore = 13,
    RLibTypeEgg = 14,
    RLibTypeFs = 15,
    RLibTypeEsil = 16,
    RLibTypeLast = 17,
}

#[repr(C)]
// #[derive(Default)]
pub struct RAnalPlugin {
    pub name: *const c_char,
    pub desc: *const c_char,
    pub license: *const c_char,
    pub arch: *const c_char,
    pub author: *const c_char,
    pub version: *const c_char,
    pub bits: c_int,
    pub esil: c_int,
    pub fileformat_type: c_int,

    pub init: Option<extern "C" fn(*mut c_void) -> c_int>,
    pub fini: Option<extern "C" fn(*mut c_void) -> c_int>,
    pub archinfo: Option<extern "C" fn(*mut c_void, usize) -> c_int>,
    pub anal_mask: Option<extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int>,
    pub preludes: Option<extern "C" fn(*mut c_void) -> *mut c_void>,

    pub op: Option<
        extern "C" fn(
            user: *mut c_void,
            op: *mut RAnalOp,
            addr: u64,
            data: *mut c_void,
            len: usize,
            mask: usize,
        ) -> c_int,
    >,
    pub cmd_ext: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub set_reg_profile: Option<extern "C" fn(*mut c_void) -> c_int>,
    pub get_reg_profile: Option<extern "C" fn(*mut c_void) -> *mut c_char>,
    pub fingerprint_bb: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub fingerprint_fcn: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub diff_bb: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub diff_fcn: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub diff_eval: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub esil_init: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub esil_post_loop: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub esil_trap: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    pub esil_fini: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
}

#[repr(C)]
pub struct RCorePlugin {
    pub name: *const c_char,
    pub desc: *const c_char,
    pub license: *const c_char,
    pub author: *const c_char,
    pub version: *const c_char,
    pub call: Option<extern "C" fn(*mut c_void, *const c_char) -> c_int>,
    pub init: Option<extern "C" fn(*mut c_void, *const c_char) -> bool>,
    pub deinit: Option<extern "C" fn(*mut c_void, *const c_char) -> bool>,
}

#[repr(C)]
pub struct RListIter {
    data: *mut c_void,
    n: *mut RListIter,
    p: *mut RListIter,
}

#[repr(C)]
pub struct RRegItem {
    name: *mut c_char,
    _type: *mut c_int,
    size: *mut c_int,
    offset: *mut c_int,
    packed_size: *mut c_int,
    is_float: *mut bool,
    flags: *mut c_char,
    index: *mut c_int,
    arena: *mut c_int,
}

#[repr(C)]
pub struct RList {
    head: *mut RListIter,
    tail: *mut RListIter,
    pub free: Option<extern "C" fn(*mut c_void)>,
    length: *mut c_int,
    sorted: *mut bool,
}

#[repr(C)]
pub struct RAnalVar {
    name: *mut c_char,
    _type: *mut c_char,
    kind: c_char,
    addr: u64,
    eaddr: u64,
    size: c_int,
    delta: c_int,
    scope: c_int,
    accesses: *mut RList,
    stores: *mut RList,
}

#[repr(C)]
pub struct RAnalValue {
    absolute: c_int,
    memref: c_int,
    base: u64,
    delta: i64,
    imm: i64,
    mul: c_int,
    sel: u16,
    reg: *mut RRegItem,
    regdelta: *mut RRegItem,
}

#[repr(C)]
pub struct RStrBuf {
    len: c_int,
    ptr: *mut c_char,
    ptrlen: c_int,
    buf: [c_char; 64],
}

#[repr(C)]
pub struct RAnalSwitchOp {
    addr: u64,
    min_val: u64,
    def_val: u64,
    max_val: u64,
    cases: *mut RList,
}

#[repr(C)]
pub struct RAnalOp {
    pub mnemonic: *mut c_char,
    pub addr: u64,
    pub _type: u32,
    pub prefix: c_int,
    pub type2: u32,
    pub stackop: c_int,
    pub cond: c_int,
    pub size: c_int,
    pub nopcode: c_int,
    pub cycles: c_int,
    pub failcycles: c_int,
    pub family: c_int,
    pub id: c_int,
    pub eob: bool,
    pub sign: bool,
    pub delay: c_int,
    pub jump: u64,
    pub fail: u64,
    pub ptr: i64,
    pub val: u64,
    pub ptrsize: c_int,
    pub stackptr: i64,
    pub refptr: c_int,
    pub var: *mut RAnalVar,
    pub src: *mut [RAnalVar; 3],
    pub dst: *mut RAnalVar,
    pub next: *mut RAnalOp,
    pub esil: RStrBuf,
    pub reg: *const c_char,
    pub ireg: *const c_char,
    pub scale: c_int,
    pub disp: u64,
    pub switch_op: *mut RAnalSwitchOp,
}

#[repr(C)]
pub struct RLibHandler {
    pub _type: c_int,
    pub desc: [c_char; 128],
    pub user: *const c_void,
    pub constructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
    pub destructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
}

#[repr(C)]
pub struct RLibPlugin {
    pub _type: c_int,
    pub file: *const c_char,
    pub data: *const c_void,
    pub handler: *const RLibHandler,
    pub dl_handler: *const c_void,
}

#[repr(C)]
pub struct RLibStruct {
    pub _type: RLibType,
    pub data: *const c_void,
    pub version: *const [u8],
}

// internal radare functions to be defined here
#[link(name = "r_cons")]
#[link(name = "r_anal")]
#[link(name = "r_core")]
extern "C" {
    pub fn r_core_anal_op(core: *mut c_void, addr: u64) -> *mut RAnalOp;
    pub fn r_anal_op_free(op: *mut RAnalOp);
    pub fn r_core_cmd_str(core: *mut c_void, cmd: *const c_char) -> *const c_char;
    pub fn r_core_is_valid_offset(core: *mut c_void, offset: u64) -> c_int;
    pub fn r_core_cmdf(core: *mut c_void, format: *const c_char, ...) -> c_int;
    pub fn r_core_cmd(core: *mut c_void, cstr: *const c_char, log: c_int) -> c_int;
    pub fn r_cons_print(cstr: *const c_char) -> c_void;
    pub fn r_cons_strcat(cstr: *const c_char) -> c_void;
    pub fn r_reg_set_profile_string(reg: *const c_void, cstr: *const c_char) -> c_void;
    pub fn r_anal_set_reg_profile(anal: *const c_void, cstr: *const c_char) -> c_int;
}

pub fn r2_cmd(core: *mut c_void, cmd: &str) -> &str {
    unsafe {
        let s = CString::new(cmd).unwrap();
        let ptr = r_core_cmd_str(core, s.as_ptr());
        let result: &CStr = CStr::from_ptr(ptr);
        match result.to_str() {
            Ok(val) => val,
            Err(_) => "",
        }
    }
}
