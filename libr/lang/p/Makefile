BINDEPS=foo
include ../../../config.mk

CFLAGS+=$(shell pkg-config --cflags r_core)
CFLAGS+=-Wall -DPREFIX=\"${PREFIX}\" -I. -Iduk

ifeq ($(OSTYPE),darwin)
CFLAGS+=-undefined dynamic_lookup
EXT_SO=dylib
else
ifeq ($(OSTYPE),windows)
EXT_SO=dll
else
EXT_SO=so
endif
endif
LUAPKG=$(shell pkg-config --list-all|awk '/lua-/{print $$1;}')
ifneq (${LUAPKG},)
CFLAGS+=$(shell pkg-config --cflags ${LUAPKG})
LUA_LDFLAGS+=$(shell pkg-config --libs ${LUAPKG})
endif

BINDEPS=
LDFLAGS_LIB=$(shell pkg-config --libs-only-L r_core) -lr_core -lr_util -shared

LANGS=$(shell ./getlangs.sh ${EXT_SO})
#LANGS=lang_python.${EXT_SO} lang_perl.${EXT_SO}

#LANGS+=lang_ruby.so
ifeq ($(HAVE_LIB_TCC),1)
LANGS+=lang_tcc.${EXT_SO}
endif
ifeq ($(HAVE_LIB_LUA5_1),1)
LANGS+=lang_lua.${EXT_SO}
endif

LANGS+=lang_duktape.$(EXT_SO)

all: ${LANGS}
	@echo "LANG ${LANGS}"

ifeq ($(OSTYPE),windows)
lang_python.${EXT_SO}:
	${CC} ${CFLAGS} -I${HOME}/.wine/drive_c/Python27/include \
	-L${HOME}/.wine/drive_c/Python27/libs -L../../core/ -lr_core \
	${LDFLAGS_LIB} -o lang_python.${EXT_SO} python.c -lpython27
else
PYCFG=../../../python-config-wrapper
PYCFLAGS=$(shell ${PYCFG} --cflags)
PYLDFLAGS=$(shell ${PYCFG} --libs) -L$(shell ${PYCFG} --prefix)/lib ${LDFLAGS_LIB}

lang_python.${EXT_SO}:
	${CC} python.c ${CFLAGS} ${PYCFLAGS} ${PYLDFLAGS} \
	${LDFLAGS} ${LDFLAGS_LIB} -fPIC -o lang_python.${EXT_SO}
endif

ifeq ($(HAVE_LIB_TCC),1)
lang_tcc.${EXT_SO}: tcc.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_tcc.${EXT_SO} tcc.c -ldl -ltcc
endif

lang_duktape.$(EXT_SO): duktape.o duk
	-$(CC) -std=c99 $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_duktape.$(EXT_SO) duktape.c

lang_lua.${EXT_SO}: lua.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_lua.${EXT_SO} lua.c ${LUA_LDFLAGS}

lang_ruby.${EXT_SO}:
	-env CFLAGS="${CFLAGS}" ruby mkruby.rb

PERLINC=$(shell perl -MConfig -e 'print $$Config{archlib}')/CORE/
lang_perl.${EXT_SO}:
	-${CC} ${CFLAGS} -I$(PERLINC) \
		-fPIC ${LDFLAGS_LIB} -o lang_perl.${EXT_SO} perl.c \
		`perl -MExtUtils::Embed -e ccopts | sed -e 's/-arch [^\s]* //g'` \
		`perl -MExtUtils::Embed -e ldopts | sed -e 's/-arch [^\s]* //g'`
# -lncurses

mrproper clean:
	-rm -f *.${EXT_SO} *.${EXT_AR} *.o
	-rm -rf *.dSYM

#R2_PLUGIN_PATH=$(shell r2 -hh| grep PLUGINS|awk '{print $$2}')
R2_PLUGIN_PATH=$(shell r2 -nqc 'e dir.plugins' -)

install:
	mkdir -p $(DESTDIR)/$(R2_PLUGIN_PATH)
	[ -n "`ls *.$(EXT_SO)`" ] && cp -f *.$(EXT_SO) $(DESTDIR)/$(R2_PLUGIN_PATH) || true

install-home:
	mkdir -p ~/.config/radare2/plugins
	[ -n "`ls *.$(EXT_SO)`" ] && \
		cp -f *.$(EXT_SO) ~/.config/radare2/plugins || true

DUKTAPE_VER=1.1.1
DUKTAPE_FILE=duktape-$(DUKTAPE_VER).tar.xz
DUKTAPE_URL=http://duktape.org/$(DUKTAPE_FILE)

duk duktape-sync duk-sync sync-dunk sync-duktape:
	rm -f $(DUKTAPE_FILE)
	wget -O $(DUKTAPE_FILE) $(DUKTAPE_URL)
	tar xJvf $(DUKTAPE_FILE)
	mkdir -p duk
	cp -f duktape-$(DUKTAPE_VER)/src/duktape.* duk/
	rm -rf $(DUKTAPE_FILE) duktape-$(DUKTAPE_VER)
