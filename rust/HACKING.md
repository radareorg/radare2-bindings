# HACKING r2rust

This document aims to clarify some concepts about what's the purpose of each crate
and how to use them.

The user can use r2pipe, r2api and r2papi and will use the system build of radare2

When passing the static feature flag it will download and build r2 in the workdir
and link r2pipe or r2api against it. This generates a single static executable with
no runtime dependencies.

## Crates

* radare2-build  : (lib) downloads and builds r2 from source (optional)
* radare2-r2api  : (lib) uses cbindgen to generate rust wrapper from r2 sources
* radare2-r2pipe : (lib) api around core.cmd() with optional static/dynamic linking
* radare2-r2papi : (lib) high level api on top of r2pipe

## Feature Flags

In order to make radare2-api.rs and r2pipe.rs use the statically linked version of radare2

```
cargo build --features static
```

--pancake
