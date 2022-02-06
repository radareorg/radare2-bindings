R2LIB=r_core

CFLAGS+=$(shell pkg-config --cflags $(R2LIB))
R2INC=$(shell pkg-config --variable=includedir $(R2LIB))

all:
	bindgen --allowlist-function='r.*' --allowlist-function='sdb_.*' --blocklist-item=IPPORT_RESERVED $(R2INC)/libr/$(R2LIB).h -- $(CFLAGS) > src/lib.rs
	cargo build
	cargo run
