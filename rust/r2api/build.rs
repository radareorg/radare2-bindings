extern crate bindgen;

use std::env;
use std::path::PathBuf;
// use pkgconfig module

fn main() {
    // Tell cargo to statically link to the radare2-build static lib
    #[cfg(feature = "static")]
    {
        // TODO: this ../radare2-bild path should be dynamically constructed
        // println!("cargo:rustc-link-search=../radare2-build/radare2/libr/");
        // println!("cargo:rustc-link-lib=r");
        println!("cargo:rustc-link-arg=../radare2-build/radare2/libr/libr.a");
    }
    #[cfg(not(feature = "static"))]
    {
        println!("cargo:rustc-link-lib=r_io");
        println!("cargo:rustc-link-lib=r_asm");
        println!("cargo:rustc-link-lib=r_arch");
        println!("cargo:rustc-link-lib=r_esil");
        println!("cargo:rustc-link-lib=r_anal");
        println!("cargo:rustc-link-lib=r_search");
        println!("cargo:rustc-link-lib=r_util");
        println!("cargo:rustc-link-lib=r_reg");
        println!("cargo:rustc-link-lib=r_debug");
        println!("cargo:rustc-link-lib=r_lang");
        println!("cargo:rustc-link-lib=r_bin");
        println!("cargo:rustc-link-lib=r_syscall");
        println!("cargo:rustc-link-lib=r_core");
        println!("cargo:rustc-link-lib=r_socket");
        println!("cargo:rustc-link-lib=r_fs");
        println!("cargo:rustc-link-lib=r_cons");
    }

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_default(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
