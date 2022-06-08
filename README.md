# radare2 API bindings

* pip install r2libr [![Python r2libr bindings 🚀](https://github.com/radareorg/radare2-bindings/actions/workflows/generate_bindings.yml/badge.svg)](https://github.com/radareorg/radare2-bindings/actions/workflows/generate_bindings.yml)
* Vala / Swig CI [![vala swig ci🚀](https://github.com/radareorg/radare2-bindings/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/radare2-bindings/actions/workflows/ci.yml)

This repository contains the native bindings generated with Valabind to use the radare2 APIs.

If you are looking for the `r2pipe` bindings, check this [repository](https://github.com/radare/radare2-r2pipe).

## Description

This directory contains the code necessary to use the r2 api from your favourite language.

Supported target languages:

* Python
  * [python-swig](python)
  * [r2libr](r2libr)
  * [ctypes](ctypes)
  * `genbind.py -o /tmp/r2bindings-output -l python`
* JavaScript
  * [node-ffi](node-ffi)
  * [node-swig](node-swig)
* Java
  * [jna](jna) Pure Java for FFI
  * [java](java) JNI native bindings
* Go
* Ruby
* Perl
* Lua
* Vala
* Rust
  * `genbind.py -o /tmp/r2bindings-output -l rust `
* NewLisp
* Guile
* OCaml

And some other experimental bindings are for:

* GIR
* C++
* C#

This package also contains the vdoc/ subdirectory which contains the
rules used to generate all [interactive html documentation](https://radare.org/vdoc).

## Dependencies

To build radare2-bindings from repository you need the following programs installed:

  * swig: enables support for python, perl, lua, java and many other
  * vala: if you want to have Vala or Genie bindings
  * valabind: required only in developer mode (not release tarball)

Release tarballs come with all the pregenerated `.cxx` files, so you have
no extra dependencies apart from the language libraries and C++ compiler.

### Using r2pm

Fortunely, all those dependencies can be installed with r2pm:
```sh
r2pm -cgi vala swig valabind
```

### Source build

To get install all dependencies do the following steps in order:

  * Install vala and swig from your distro

```sh
arch$ sudo pacman -S swig valac
deb$ sudo apt install -y swig valac
mac$ brew install swig valac
```

Or install

  * Install [latest release](https://live.gnome.org/Vala) of Vala from tarball or git
  * Fetch valabind from the repository:

```sh
$ git clone https://github.com/radare/valabind
$ cd valabind
$ make
$ sudo make install PREFIX=/usr
```

## radare2-bindings

If you compile from the repo you need the latest version of valabind and then:
```
./configure --prefix=/usr
```

You can select the languages you want to compile with `--enable={list-of-langs}`
```
./configure --prefix=/usr --enable=python
make
```

## r2libr (python)

r2libr are the most complete **python bindings** generated from source with all `libr` dynamic libraries bundled in a wheel.

You may have a try without the need to install radare2:

```bash
pip3 install --upgrade r2libr
```

For details, see [r2libr](https://github.com/radareorg/radare2-bindings/tree/master/r2libr).

## Experimental radare2 bindgen

### Introduction

This script allows to generate native bindings for these languages directly from radare2 C headers:

 - Python (uses [ctypeslib2](https://github.com/trolldbois/ctypeslib))
 - Rust (uses [rust-bindgen](https://github.com/rust-lang-nursery/rust-bindgen))
 - Go (uses [c-for-go](https://github.com/xlab/c-for-go))
 - Haskell (uses [c2hs](https://github.com/haskell/c2hs))

More languages are planned, in particular:

 - Ruby - I wanted to use [ffi-gen](https://github.com/neelance/ffi_gen) but it needs revival and update to the modern Ruby and Clang.
 - OCaml - needs to be written
 - Lua - maybe [LuaAutoC](https://github.com/orangeduck/LuaAutoC) can be used, I don't know.

### Usage

```sh
genbind.py -o /tmp/r2bindings-output
```

The tool required `radare2` to be installed and takes the include directory from the output of `r2 -H`
It is possible also specify the particular languages, for example:
```sh
genbind.py -o /tmp/r2bindings-output -l go rust python
```

## PYTHON

To select the version of python to compile for use the PYTHON_CONFIG
environment variable as follows:
```sh
$ ./configure --prefix=/usr --enable-devel
$ cd python
$ PYTHON_CONFIG=python3.2-config make
$ su -
# PYTHON_CONFIG=python3.2-config make install
```

## RANDOM NOTES

The valabind integration forces us to do some changes in the r2 API.

These api changes are for:

  - Avoid keywords in function names

    Every language has its own keywords, r2api should try to workaround
    all those keywords to avoid collisions for bindings.

    Example: `use`, `del`, `from`, `continue`, etc..

    TODO: we need to review APIs, find better names for functions using
    those keywords, etc..

  - Review basic data structures

    Linked lists, hash tables, r_db, arrays, ... must be reviewed to
    fit with vala and swig basics to be able to use them with simple
    APIs or integrate them with the syntax sugar of the target language.

    Example:

```vala
  foreach (var foo in binls.get_symbols ()) {
	print ("%s 0x%08"PFMT64x"\n", foo.name, foo.offset);
  }
```

  - Unit testing

    Having bindings for python, perl, ruby, .. is good for unit testing
    because it hardly simplifies the way to test APIs, find bugs, ...

    TODO: write unit testing frameworks for perl, ruby, python, etc..

  - API unification for all languages

    All the previous development points are meant to reduce code in r2,
    avoid syntax exceptions, simplify api usage, and much moar ;)

SWIG is not complete, there are still so many bugs to fix and so many
unimplemented stuff. Here's a list of the most anoying things of it:

  - `unsigned char *` : not implemented
