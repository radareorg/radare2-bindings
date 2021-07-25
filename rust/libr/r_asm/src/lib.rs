// extern crate libc;
// use libc::size_t;

#[link(name = "r_asm")]
extern {
    #[no_mangle]
    fn r_asm_new(source_length: i32) -> i32;
}

struct Foo {
   test: i32
}

#[no_mangle]
pub extern "C" fn r3_asm_new() -> i32 {
    unsafe {
        let a = r_asm_new(32);
        println!("=> {}", a);
    }
    42
}

#[test]
fn it_works() {
    unsafe {
        let a = r_asm_new(32);
        println!("=> {}", a);
    }
}
