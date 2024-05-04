CARGO=cargo

.PHONY: all test_static pub

all:
	$(CARGO) fmt
	$(CARGO) build
	$(CARGO) run

test_static:
	$(CARGO) run --features=static

pub:
	$(CARGO) publish
