/*
 * Copyright © 2023 pancake
 * Licence: MIT
 */

use std::process::Command;

use std::{env, io::Error, path::Path};

fn system(cmd: &str) -> Result<(), Error> {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("failed to execute process");
    Ok(())
}

/// private function to retry download in case of error.
fn download_and_use_devkit_internal(
    _kind: &str,
    version: &str,
    force_download: bool,
) -> Result<String, Error> {
    let out_dir = match env::var_os("OUT_DIR") {
        Some(out_dir) => out_dir,
        // None => OsString("."),
        None => ".".into(),
    };
    if force_download {
        println!("No r2sdk download support yet");
    }
    if Path::new("radare2").is_dir() {
        system("cd radare2 && git pull")?;
    } else {
        system("git clone https://github.com/radareorg/radare2")?;
    }

    let r2version = match env::var_os("RADARE2_VERSION") {
        None => version,
        Some(r2v) => {
            let s = String::from(r2v.to_str().unwrap());
            return Ok(s);
        }
    };
    // specify commit, branch or tag
    if r2version != "" {
        system(format!("cd radare2 && git checkout {}", r2version).as_str())?;
    }
    if let Some(_gpl) = env::var_os("RADARE2_GPL") {
        system("cd radare2 && cp dist/plugins.nogpl.cfg plugins.cfg")?;
    }
    system("cd radare2 && sys/static.sh")?;
    // println!("cargo:rustc-link-search={}", out_dir.to_string_lossy());
    // println!("cargo:rustc-link-lib=static=frida-{kind}");
    println!("cargo:rustc-link-search=static=radare2/libr/libr.a");

    Ok(out_dir.to_string_lossy().to_string())
}

#[must_use]
pub fn download_and_use_devkit(kind: &str, version: &str) -> String {
    download_and_use_devkit_internal(kind, version, false)
        .or_else(|e| {
            println!("cargo:warning=Failed to unpack devkit: {e}, retrying download...");
            download_and_use_devkit_internal(kind, version, true)
        })
        .expect("cannot extract the devkit tar.gz")
}

#[test]
fn test_build() {
    let foo = download_and_use_devkit("r2", "master"); // 5.8.6");
    assert!(1 == 1);
}

#[test]
fn test_build2() {
    println!("testing");
}
