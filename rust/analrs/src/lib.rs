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

const MY_NAME : *const c_char = b"anal-rs\0" as *const [u8] as *const c_char;
const R2_VERSION: &'static [u8] = b"1.7.0-git\0";
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

const R_ANAL_PLUGIN: RCorePlugin = RCorePlugin {
    name : MY_NAME,
    desc : MY_DESC as *const [u8] as *const c_char,
    license : MY_LICENSE as *const [u8] as *const c_char,
    author : MY_AUTHOR as *const [u8] as *const c_char,
    version : MY_VERSION as *const [u8] as * const c_char,
    call: Some(_anal_call),
    init: None,
    deinit: None
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    _type : RLibType::RLibTypeCore ,
    data : ((&R_ANAL_PLUGIN) as *const RCorePlugin) as *const c_void,
    version : R2_VERSION
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
