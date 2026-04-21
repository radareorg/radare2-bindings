LANG=node-ffi
MODVER=$(shell node -e 'console.log(JSON.parse(require("fs").readFileSync("package.json"))["version"])')
LANG_EXT=js
LIBS_PFX=
FORCE_SOEXT=1
SAVED=index.js

# Modules we generate via valabind (--node-ffi). The resulting `<mod>.js`
# files are reference bindings; the runtime entry point (index.js) talks to
# libr via koffi directly so it works on any modern Node without a native
# rebuild step.
MODULES=r_core r_bin r_asm r_io

.PHONY: all bar gen test hello clean node_modules
bar: node_modules all

all: gen

gen: $(MODULES:=.js)

%.js: ../vapi/%.vapi
	cd .. && DIST=1 sh do-swig.sh node-ffi $*

node_modules:
	npm install

test: node_modules gen
	node examples/hello.js

hello: test

npm-publish: clean
	${MAKE}
	npm publish

unpublish: clean
	${MAKE}
	npm unpublish @${MODVER}

clean:
	rm -f r_*.js
