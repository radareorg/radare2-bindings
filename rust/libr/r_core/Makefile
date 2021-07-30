R2LIB=r_core

CFLAGS+=$(shell pkg-config --cflags $(R2LIB))
R2INC=$(shell pkg-config --variable=includedir $(R2LIB))

all:
	@bindgen -h > /dev/null 2>&1 || cargo install bindgen
	bindgen $(R2INC)/libr/$(R2LIB).h -- $(CFLAGS) > src/lib.rs
	#bindgen $(R2INC)/libr/r_cons.h -- $(CFLAGS) > src/lib_cons.rs
	cargo build
	cargo run
