include ../config.mk

# Modern go build: each module lives in its own package directory
# under go/<mod>/, built with cgo via `go build`. `make` generates the
# SWIG wrappers, stages them under the package directory with cgo
# directives prepended, then runs `go build` on each package.
MODULES=r_bin r_core r_asm r_io

all: $(MODULES)

define PKG_RULE
.PHONY: $(1)
$(1): $(1)/.stamp

$(1)/.stamp: ../vapi/$(1).vapi
	cd .. && DIST=1 sh do-swig.sh go $(1)
	mkdir -p $(1)
	mv -f $(1).go $(1).i $(1)_wrap.cxx $(1)/
	./inject-cgo.sh $(1)/$(1).go $(1)
	printf 'module %s\n\ngo 1.21\n' $(1) > $(1)/go.mod
	cd $(1) && go build ./...
	touch $(1)/.stamp
endef

$(foreach m,$(MODULES),$(eval $(call PKG_RULE,$(m))))

# Build and run a Go test program that links against the generated
# bindings. Uses r_core because r_bin alone has no IO backend.
rbintest test: $(MODULES)
	cd test && go build -o test-r_bin . && ./test-r_bin /bin/ls

hello: r_core
	cd hello && go build -o hello . && ./hello

clean:
	rm -rf $(MODULES) test/test-r_bin hello/hello
	rm -f r_*.go r_*_wrap.cxx r_*.i _r_*.so r_*.${SOEXT}

.PHONY: all clean test rbintest hello
