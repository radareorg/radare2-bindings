use r2api::{r_core_new,r_core_cmd0,r_cons_flush,r_core_free, r_io_new};
use std::ffi::CString;

macro_rules! c_str {
    ($lit:expr) => {
        std::ffi::CStr::from_ptr(concat!($lit, "\0").as_ptr() as *const i8).as_ptr()
    }
}



fn main() {
    println!("Hello RCore");
    unsafe {
        let c = r_core_new();
        let pangram = "?E Hello World\x00".as_ptr() as *const i8;
	let _ = r_io_new ();
        r_core_cmd0(c, pangram);
        r_core_cmd0(c, CString::new("b").unwrap().as_ptr());
        r_core_cmd0(c, c_str!("?e woot"));
        r_cons_flush();
        r_core_free(c);
    }
}
