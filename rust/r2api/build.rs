// Copyright 2024 pancake, terorie
//
// Parts of this build config (the pkg-config stuff) were copied
// from Mozilla's neqo-crypto from here:
// https://github.com/mozilla/neqo/blob/main/neqo-crypto/build.rs
//
// Their original license terms are:
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let mut pkgconf_args = vec!["--cflags", "--libs"];

    #[cfg(feature = "static")]
    pkgconf_args.push("--static");

    pkgconf_args.push("r_core");

    let cfg = Command::new("pkg-config")
        .args(pkgconf_args)
        .output()
        .expect("Can't find r_core")
        .stdout;
    let cfg_str = String::from_utf8(cfg).unwrap();

    let mut flags: Vec<String> = Vec::new();
    for f in cfg_str.split(' ') {
        if let Some(include) = f.strip_prefix("-I") {
            flags.push(String::from(f));
            println!("cargo:include={include}");
        } else if let Some(path) = f.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(lib) = f.strip_prefix("-l") {
            // Work around bug where pkg-config provides dylibs even if --static is passed
            let skip = cfg!(feature = "static") && lib.starts_with("r_");
            if !skip {
                println!("cargo:rustc-link-lib=dylib={lib}");
            }
        } else if f.ends_with(".a") {
            println!("cargo:rustc-link-arg={f}")
        } else {
            println!("cargo:warning=Unknown flag from pkg-config: {f}");
        }
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
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("r_.*")
        .allowlist_function("sdb_.*")
        .blocklist_item("IPPORT_RESERVED")
        .clang_args(flags)
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
