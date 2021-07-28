#![allow(dead_code)]
extern crate libc;
extern crate serde;
extern crate serde_json;


use libc::*;
use std::str;
use std::ffi::CStr;

mod bb;
mod anal;
mod fcn;
mod radare2;

use radare2::*;

const MY_NAME: &'static [u8] = b"v850.rs\0";
const MY_ARCH: &'static [u8] = b"v850\0";
const R2_VERSION: &'static [u8] = b"5.4.0-git\0";
const MY_DESC : &'static [u8] = b"Analysis plugin\0";
const MY_LICENSE : &'static [u8] = b"MIT\0";
const MY_VERSION : &'static [u8] = b"0.1.0\0";
const MY_AUTHOR : &'static [u8] = b"defragger <rlaemmert@gmail.com>\0";

fn analyze_binary (core: *mut c_void) -> c_int {
    let mut anal = anal::Anal::new(core);
    anal.analyze();

    for fcn in &anal.functions {
        fcn.dump_r2_commands();
    }
    anal.print_info();
    return 1;
}

extern "C" fn _anal_op(_user: *mut c_void, _op: *mut RAnalOp, _addr: u64, _data: *mut c_void, _len: usize, _mask: usize) -> c_int {
unsafe {
	(*_op).mnemonic = libc::strdup("rustop r0, 123\0".as_ptr() as *const i8);
	(*_op).size = 4;
	(*_op)._type = R_ANAL_OP_TYPE_NOP;
}
	return 4;
}

extern "C" fn _anal_call (user: *mut c_void, input: *const c_char) -> c_int {
    let c_str: &CStr = unsafe { CStr::from_ptr(input) };
    let bytes = c_str.to_bytes();
    let input = str::from_utf8(bytes).unwrap();
    if input.starts_with("aaR") {
        analyze_binary (user);
        return 1;
    }
    return 0;
}

/*
SHOULD BE DEPRECATED
extern "C" fn _anal_getreg(_user: *mut c_void) -> *mut c_char {
   let p = "=PC rip\n\
  =BP rax\n\
  =SP rsp\n\
  =A0 rax\n\
  =A1 rbx\n\
  gpr rax .32 0 0\n\
  gpr rbx .32 4 0\n\
  gpr rip .32 8 0\n\
  gpr rsp .32 12 0\n";
unsafe {
   return libc::strdup(p.as_ptr() as *const i8);
}
   // return b"\0" as *const u8 as *const c_char ;
}
*/

extern "C" fn _anal_setreg(_user: *mut c_void) -> c_int {
   let p = "=PC rip\n\
  =BP rax\n\
  =SP rsp\n\
  =R0 rax\n\
  =A0 rax\n\
  =A1 rbx\n\
  gpr rax .32 0 0\n\
  gpr rbx .32 4 0\n\
  gpr rip .32 8 0\n\
  gpr rsp .32 12 0\n\0";
unsafe {
r_anal_set_reg_profile (_user, p.as_ptr() as *const i8);
}
   return 0;
}

const R_ANAL_PLUGIN: RAnalPlugin = RAnalPlugin {
    name : MY_NAME as *const [u8] as *const c_char,
    desc : MY_DESC as *const [u8] as *const c_char,
    license : MY_LICENSE as *const [u8] as *const c_char,
    arch: MY_ARCH as *const [u8] as *const c_char,
    author : MY_AUTHOR as *const [u8] as *const c_char,
    version : MY_VERSION as *const [u8] as * const c_char,
    bits: 64,
    esil: 1,
    fileformat_type: 0,
    init: None,
    fini: None,
    archinfo: None,
    anal_mask: None,
    preludes: None,
    op: Some(_anal_op),

    cmd_ext: None,
    diff_bb: None,
    diff_eval: None,
    diff_fcn: None,
    esil_fini: None,
    esil_init: None,
    esil_trap: None,
    esil_post_loop: None,
    fingerprint_bb: None,
    fingerprint_fcn: None,
    get_reg_profile: None,
    // get_reg_profile: Some(_anal_getreg),
    // set_reg_profile: None,
    set_reg_profile: Some(_anal_setreg),
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    _type : RLibType::RLibTypeAnal ,
    data : ((&R_ANAL_PLUGIN) as *const RAnalPlugin) as *const c_void,
    version : R2_VERSION
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
