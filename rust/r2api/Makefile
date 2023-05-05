R2LIB=r_core
BINDGEN=bindgen
CARGO=cargo

CFLAGS+=$(shell pkg-config --cflags $(R2LIB))
R2INC=$(shell pkg-config --variable=includedir $(R2LIB))

BINDGEN_FLAGS+=--allowlist-function='r_.*'
BINDGEN_FLAGS+=--allowlist-function='sdb_.*'
BINDGEN_FLAGS+=--blocklist-item=IPPORT_RESERVED

# BINDGEN_FLAGS+= --opaque-type 'std::.*'

all:
	$(BINDGEN) $(BINDGEN_FLAGS) $(R2INC)/libr/$(R2LIB).h -- $(CFLAGS) > src/lib.rs
	$(CARGO) build
	$(CARGO) run

pub:
	$(CARGO) publish --allow-dirty
