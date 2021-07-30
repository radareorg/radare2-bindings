// pub mod r_asm;
// mod r_asm;
use r_core::*;

fn main() {
    println!("Hello RCore");
    unsafe {
        let c = r_core_new();
        let pangram = "?E Hello World\x00".as_ptr() as *const i8;
        r_core_cmd0(c, pangram);
        r_cons_flush();
        r_core_free(c);
    }
}
