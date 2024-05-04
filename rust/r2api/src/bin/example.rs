use r2api::{r_cons_flush, r_core_cmd0, r_core_free, r_core_new, r_io_new};
use std::ffi::CStr;

macro_rules! static_cstr {
    ($str: tt) => {
        CStr::from_bytes_with_nul_unchecked(concat!($str, "\x00").as_bytes()).as_ptr()
    };
}

fn main() {
    unsafe {
        let c = r_core_new();
        let _ = r_io_new();
        r_core_cmd0(c, static_cstr!("?E Hello World"));
        r_core_cmd0(c, static_cstr!("b"));
        r_core_cmd0(c, static_cstr!("?e woot"));
        r_cons_flush();
        r_core_free(c);
    }
}
