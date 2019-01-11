BINDEPS=foo
include ../../../config.mk

CFLAGS+=$(shell pkg-config --cflags r_core)
CFLAGS+=-DPREFIX=\"${PREFIX}\"

DUK_CFLAGS+=-Wall -DPREFIX=\"${PREFIX}\" -I. -Iduk

R2PM_PLUGDIR?=$(shell r2 -H R2_USER_PLUGINS)
EXT_SO?=$(shell r2 -H LIBEXT)

ifeq ($(EXT_SO),)
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
endif

LUAPKG=$(shell pkg-config --list-all|awk '/lua5|lua5-/{print $$1;}')
ifneq (${LUAPKG},)
CFLAGS+=$(shell pkg-config --cflags ${LUAPKG})
LUA_LDFLAGS+=$(shell pkg-config --libs ${LUAPKG})
endif

BINDEPS=
LDFLAGS_LIB=$(shell pkg-config --libs-only-L r_core) -lr_core -lr_io -lr_util -shared -lr_asm

WANT_LUA=$(shell grep -q lua ../../../supported.langs && echo 1)
#WANT_JS=$(shell grep -q js ../../../supported.langs && echo 1)
WANT_DUK=$(shell grep -q duktape ../../../supported.langs && echo 1)
WANT_PY=$(shell grep -q python ../../../supported.langs && echo 1)
WANT_CS=$(shell grep -q cs ../../../supported.langs && echo 1)

LANGS=$(shell ./getlangs.sh ${EXT_SO})
#LANGS=lang_python.${EXT_SO} lang_perl.${EXT_SO}

#LANGS+=lang_ruby.so
ifeq ($(HAVE_LIB_TCC),1)
LANGS+=lang_tcc.${EXT_SO}
endif

ifeq ($(WANT_LUA),1)
ifeq ($(HAVE_LIB_LUA5_1),1)
LANGS+=lang_lua.${EXT_SO}
endif
endif

ifeq ($(WANT_CS),1)
LANGS+=lang_csharp.${EXT_SO}
endif

ifeq ($(WANT_DUK),1)
LANGS+=lang_duktape.$(EXT_SO)
endif

all: $(LANGS)
	@echo "LANG ${LANGS}"

PYVER?=2
ifeq ($(OSTYPE),windows)
lang_python.${EXT_SO}:
	${CC} ${CFLAGS} -I${HOME}/.wine/drive_c/Python27/include \
	-L${HOME}/.wine/drive_c/Python27/libs \
	$(shell pkg-config --cflags --libs r_reg r_core r_cons) \
	${LDFLAGS_LIB} -o lang_python.${EXT_SO} python.c -lpython27
else
PYCFG=../../../python-config-wrapper
PYSO=lang_python$(PYVER).${EXT_SO}
PYCFLAGS=$(shell PYVER=$(PYVER) ${PYCFG} --cflags) -DPYVER=${PYVER}
PYLDFLAGS=$(shell PYVER=$(PYVER) ${PYCFG} --libs) 
PYLDFLAGS+=-L$(shell PYVER=$(PYVER) ${PYCFG} --prefix)/lib
PYLDFLAGS+=${LDFLAGS_LIB}

lang_python.$(EXT_SO) $(PYSO):
	${CC} python.c ${CFLAGS} ${PYCFLAGS} ${PYLDFLAGS} \
	$(shell pkg-config --cflags --libs r_reg r_core r_cons) \
	${LDFLAGS} ${LDFLAGS_LIB} -fPIC -o $(PYSO)
endif

py python:
	rm -f $(PYSO)
	$(MAKE) $(PYSO)

py-install python-install:
	mkdir -p ${R2PM_PLUGDIR}
	cp -f $(PYSO) ${R2PM_PLUGDIR}

py-uninstall python-uninstall:
	rm -f ${R2PM_PLUGDIR}/$(PYSO)

ifeq ($(HAVE_LIB_TCC),1)
lang_tcc.${EXT_SO}: tcc.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_tcc.${EXT_SO} tcc.c -ldl -ltcc
else
lang_tcc.${EXT_SO}: ;
	# do nothing
endif

duktape:
	$(MAKE) lang_duktape.$(EXT_SO)

lang_duktape.$(EXT_SO): duktape.o duk
	-$(CC) -std=c99 $(DUK_CFLAGS) $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_duktape.$(EXT_SO) duktape.c

lua lang_lua.${EXT_SO}: lua.o
	-${CC} ${CFLAGS} -fPIC ${LDFLAGS_LIB} -o lang_lua.${EXT_SO} lua.c ${LUA_LDFLAGS}

lua-install:
	mkdir -p ${R2PM_PLUGDIR}/lua
	cp -f lang_lua.${EXT_SO} ${R2PM_PLUGDIR}
	cp -f lua/*.lua ${R2PM_PLUGDIR}/lua

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
#R2_PLUGIN_PATH=$(shell r2 -nqc 'e dir.plugins' -)
R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)

install:
	mkdir -p $(DESTDIR)/$(R2_PLUGIN_PATH)
	[ -n "`ls *.$(EXT_SO)`" ] && cp -f *.$(EXT_SO) $(DESTDIR)/$(R2_PLUGIN_PATH) || true
	cp -f radare.lua $(DESTDIR)/$(R2_PLUGIN_PATH)

install-home:
	mkdir -p ${R2PM_PLUGDIR}
	[ -n "`ls *.$(EXT_SO)`" ] && \
		cp -f *.$(EXT_SO) ${R2PM_PLUGDIR} || true

DUKTAPE_VER=2.3.0
DUKTAPE_FILE=duktape-$(DUKTAPE_VER).tar.xz
DUKTAPE_URL=http://duktape.org/$(DUKTAPE_FILE)

duk duktape-sync duk-sync sync-dunk sync-duktape:
	rm -f $(DUKTAPE_FILE)
	wget -O $(DUKTAPE_FILE) $(DUKTAPE_URL)
	tar xJvf $(DUKTAPE_FILE)
	mkdir -p duk
	cp -f duktape-$(DUKTAPE_VER)/src/duktape.* duk/
	cp -f duktape-$(DUKTAPE_VER)/src/duk_config.h duk/
	rm -rf $(DUKTAPE_FILE) duktape-$(DUKTAPE_VER)

PCP=/Library/Frameworks/Mono.framework/Versions/Current/lib/pkgconfig/

mono csharp lang_csharp.$(EXT_SO):
	$(CC) -fPIC $(LDFLAGS_LIB) -o lang_csharp.$(EXT_SO) \
		$(shell pkg-config --cflags --libs r_util) csharp.c

csharp-install mono-install:
	mkdir -p ${R2PM_PLUGDIR}
	cp -f lang_csharp.$(EXT_SO) ${R2PM_PLUGDIR}

csharp-uninstall mono-uninstall:
	rm -f ${R2PM_PLUGDIR}/lang_csharp.$(EXT_SO)
