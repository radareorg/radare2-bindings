// pub mod r_asm;
// mod r_asm;
use r_asm::r_asm_new;
use r_asm::r_asm_free;

fn main() {
	println!("Hello RAsm");
	unsafe {
		let a = r_asm_new ();
		println!("Hello World");
		r_asm_free (a);
	}
}
