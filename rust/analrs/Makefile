SOEXT=$(shell r2 -H LIBEXT)
USER_PLUGINS=$(shell r2 -H USER_PLUGINS)

all:
	cargo build --release
	$(MAKE) install

install:
	mkdir -p $(USER_PLUGINS)/
	cp -f target/release/libanalrs.$(SOEXT) $(USER_PLUGINS)/

uninstall:
	rm -f $(RHOMEDIR)/plugins/libanalrs.$(SOEXT)

clean:
	cargo clean
