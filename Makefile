# Requires ./configure
include config.mk

PREFIX?=/usr
PYTHON_CONFIG=python3.2-config

ifneq ($(shell bsdtar -h 2>/dev/null|grep bsdtar),)
TAR=bsdtar cJvf
else
TAR=tar -cJvf
endif

W32PY="${HOME}/.wine/drive_c/Python34/"

ifneq ($(shell grep valac supported.langs 2>/dev/null),)
INSTALL_TARGETS=install-vapi
else
INSTALL_TARGETS=
endif
INSTALL_TARGETS+=install-plugins

LANGS=
# Experimental:
# LANGS+=gir
ALANGS=awk gir python ruby perl lua go java guile php5 ocaml
.PHONY: ${ALANGS}

define ADD_lang
ifneq ($(shell grep $(1) supported.langs 2>/dev/null),)
LANGS+=$(1)
INSTALL_TARGETS+=install-$(1)
endif
endef

ifneq ($(shell grep python supported.langs 2>/dev/null),)
INSTALL_EXAMPLE_TARGETS+=install-python-examples
endif

$(foreach p,${ALANGS},$(eval $(call ADD_lang,$(p))))

.PHONY: ${INSTALL_TARGETS} ${INSTALL_EXAMPLE_TARGETS} ${LANG}

LANGS=$(shell cat supported.langs 2>/dev/null)
all: supported.langs
	$(MAKE) -C libr/lang/p
	@for a in ${LANGS} ; do \
		[ $$a = valac ] && continue; \
		(cd $$a && ${MAKE} ) ; done

supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh

check:
	rm -f supported.langs
	${MAKE} supported.langs

check-w32:
	if [ ! -d "${W32PY}/libs" ]; then \
		wget https://www.python.org/ftp/python/3.4.4/python-3.4.4.msi ; \
		msiexec /i python-3.4.4.msi /qn ; \
	fi

w32:
	cd python && ${MAKE} w32

DSTNAME=radare2-bindings-w32-$(VERSION)
DST=../$(DSTNAME)/Python34/Lib/site-packages/r2

w32dist:
	rm -rf ../${DSTNAME}
	mkdir -p ${DST}
	cp -f python/*.dll ${DST}
	cp -f python/r_*.py ${DST}
	:> ${DST}/__init__.py
	cd ${DST} ; for a in *.dll ; do mv $$a `echo $$a | sed -e s,dll,pyd,g` ; done
	#Copying over libr_*.dll libs as bindings need them in same dir as .py
	for a in `find $$PWD/../libr -name libr*.dll | grep -e dll$$`; do cp $$a ${DST} ; done
	cd .. ; zip -r $(DSTNAME).zip $(DSTNAME)

.PHONY: w32dist dist w32 check check-w32 vdoc vdoc_pkg

PKG=radare2-bindings-$(VERSION)

dist:
	git clone . "$(PKG)"
	rm -rf "$(PKG)/.git"
	${TAR} "$(PKG).tar.xz" "$(PKG)"
	rm -rf "$(PKG)"
	
old-dist:
	PKG=radare2-bindings-${VERSION} ; \
	DIR=`basename $$PWD` ; \
	FILES=`git ls-files | sed -e s,^,radare2-bindings-${VERSION}/,` ; \
	CXXFILES=`cd .. ; find radare2-bindings | grep -e cxx$$ -e py$$ | sed -e "s,radare2-bindings/,$${PKG}/,"` ; \
	cd .. && mv $${DIR} $${PKG} && \
	echo $$FILES ; \
	${TAR} $${PKG}.tar.xz $${FILES} ; \
	mv $${PKG} $${DIR}
#$${CXXFILES} ; 

# TODO: valadoc
vdoc:
	-rm -rf vdoc
	cat vapi/r_*.vapi > libr.vapi
	valadoc --package-version=${VERSION} --package-name=libr -o vdoc libr.vapi
	sed -e 's,font-family:.*,font-family:monospace;,' vdoc/style.css > vdoc/.style.css
	mv vdoc/.style.css vdoc/style.css
	-rm -f libr.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

vdoc_pkg:
	rm -rf vdoc
	valadoc -o vdoc vapi/*.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

# TODO: unspaguetti this targets
.PHONY: python3
python3:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} PYTHON_CONFIG=${PYTHON_CONFIG}) || true

${ALANG}::
	cd $@ && ${MAKE}

go::
	@-[ -x "${GOBIN}/5g" -o -x "${GOBIN}/6g" -o -x "${GOBIN}/8g" ]

test:
	cd perl && ${MAKE} test
	cd python && ${MAKE} test
	cd ruby && ${MAKE} test
	cd lua && ${MAKE} test
	cd guile && ${MAKE} test
	cd go && ${MAKE} test
	cd java && ${MAKE} test

PYTHON?=`pwd`/python-wrapper
PYTHON_VERSION?=$(shell ${PYTHON} --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2)
PYTHON_PKGDIR=$(shell ${PYTHON} mp.py)
PYTHON_INSTALL_DIR=${DESTDIR}/${PYTHON_PKGDIR}/r2

.PHONY: purge purge-python install-cxx install-plugins

purge: purge-python purge-java

install-plugins:
	$(MAKE) -C libr/lang/p install

install-cxx:
	@echo TODO: install-cxx

purge-java:
	cd java && ${MAKE} purge

purge-python:
	[ -n "${PYTHON_PKGDIR}" ] && \
	rm -rf ${DESTDIR}/${LIBDIR}/python${PYTHON_VERSION}/*-packages/r2
	rm -rf ${PYTHON_INSTALL_DIR}

HOST_OS=$(shell uname)
install-python:
	test -f python/_r_core.${SOEXT}
	E=${SOEXT} ; \
	if [ $(HOST_OS) = Darwin ];then \
		for a in python/*.dylib ; do cp $$a `echo $$a | sed -e s,dylib,so,` ; done ; \
		E=so ; \
	fi ; \
	echo "Installing python${PYTHON_VERSION} r2 modules in ${PYTHON_INSTALL_DIR}" ; \
	mkdir -p ${PYTHON_INSTALL_DIR} ; \
	: > ${PYTHON_INSTALL_DIR}/__init__.py ; \
	cp -rf python/r_*.py python/*.$$E ${PYTHON_INSTALL_DIR}

install-ctypes:
	test -f ctypes/r_core.py
	echo "Installing python${PYTHON_VERSION} r2 modules in ${PYTHON_INSTALL_DIR}" ; \
	mkdir -p ${PYTHON_INSTALL_DIR} ; \
	: > ${PYTHON_INSTALL_DIR}/__init__.py ; \
	cp -rf ctypes/r_*.py ${PYTHON_INSTALL_DIR}

uninstall-ctypes:
	rm -rf ${PYTHON_INSTALL_DIR}

LUAPATH=$(shell strings `../sys/whereis.sh lua`| grep lib/lua | cut -d ';' -f 2 | grep '.so'  | cut -d '?' -f 1)

LUAPKG=$(shell pkg-config --list-all | awk '/^lua[^a-zA-Z]/{printf($$1 "|");}' | sed -e s/\|$$//)
ifneq (${LUAPKG},)

lua-install install-lua:
	for lua_pkg in `echo "${LUAPKG}" | sed -e s/\|/\\\n/`; do \
		_LUADIR=`pkg-config --variable=INSTALL_CMOD $$lua_pkg`; \
		_LUAVER=`pkg-config --variable=V $$lua_pkg`; \
		mkdir -p ${DESTDIR}$$_LUADIR ; \
		echo "Installing lua r2 modules... ${DESTDIR}$$_LUADIR" ; \
		for f in `ls lua/*so*$$_LUAVER`; do \
			tmp=$${f%%.*}; \
			cp -rf $$f ${DESTDIR}$$_LUADIR/$${tmp##*/}.so; \
		done; \
	done
else
lua-install install-lua:
endif

install-go:
	@. ./go/goenv.sh ; \
	if [ -n "$${GOROOT}" -a -n "$${GOOS}" -a -n "$${GOARCH}" ]; then \
		echo "Installing r2 modules in $${GOROOT}/pkg/$${GOOS}_$${GOARCH}" ; \
		cp -f go/*.a go/*.${SOEXT} $${GOROOT}/pkg/$${GOOS}_$${GOARCH} ; \
	else \
		echo "You have to set the following vars: GOROOT, GOOS and GOARCH" ; \
	fi

install-java:
	cd java && ${MAKE} install

RUBYPATH=$(shell gem environment gemdir | sed -e s,gems/,,)
install-ruby:
	echo "Installing radare2 Ruby modules..."
	rm -rf ${DESTDIR}${RUBYPATH}/r2
	mkdir -p ${DESTDIR}${RUBYPATH}/r2
	cp -rf ruby/* ${DESTDIR}${RUBYPATH}/r2

PERLPATH=$(DESTDIR)/$(shell perl -e 'for (@INC) { print "$$_\n" if ((/lib(64)?\/perl5/ && !/local/) || (/Library/)); }'|head -n 1)

install-perl:
	# hack for slpm
	@echo "Installing perl r2 modules..."
	mkdir -p $(PERLPATH)/r2
	cp -rf perl/*.${SOEXT} $(PERLPATH)/r2
	cp -rf perl/*.pm $(PERLPATH)/r2

install-vapi:
	mkdir -p ${DESTDIR}${PREFIX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi

uninstall-vapi:
	( cd vapi ; for a in *.vapi *.deps ; do \
		F=${DESTDIR}${PREFIX}/share/vala/vapi/$$a ; \
		if [ -f "$F" ]; then \
			echo "rm -f \"$F\"" ; \
			rm -f "${DESTDIR}${PREFIX}/share/vala/vapi/$$a" ; \
		fi ; \
	done )

AWKDIR=${DESTDIR}${PREFIX}/lib/radare2/${VERSION}/awk
install-awk:
	mkdir -p ${AWKDIR}
	sed -e 's,@AWKDIR@,${AWKDIR},g' < awk/r2awk > ${DESTDIR}${PREFIX}/bin/r2awk
	cp -f awk/* ${AWKDIR}/

install-gir:
	cd gir && ${MAKE} install

install-php5 install-guile:
	@echo TODO install-$@

EXAMPLEDIR=${DESTDIR}${PREFIX}/share/radare2-swig

install-examples: ${INSTALL_EXAMPLE_TARGETS}
	mkdir -p ${EXAMPLEDIR}/vala
	cp -rf vapi/t/*.vala vapi/t/*.gs ${EXAMPLEDIR}/vala

install-python-examples:
	mkdir -p ${EXAMPLEDIR}/python
	cp -rf python/test-*.py ${EXAMPLEDIR}/python

install: ${INSTALL_TARGETS}

deinstall uninstall:
	cd vapi/ ; for a in *.vapi *.deps ; do rm -f ${DESTDIR}${PREFIX}/share/vala/vapi/$$a ; done
	rm -rf ${EXAMPLEDIR}

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	$(MAKE) -C libr/lang/p clean
	@for a in $(LANGS); do \
		if [ -d $$a ]; then \
		echo "Cleaning $$a " ; \
		( cd $$a && ${MAKE} clean ) ; \
		fi ; \
	done

mrproper:
	for a in $(LANGS); do cd $$a ; ${MAKE} mrproper; cd .. ; done

version:
	@echo ${VERSION}

.PHONY: $(LANGS) $(ALANGS)
.PHONY: clean mrproper all vdoc
.PHONY: oldtest test
.PHONY: w32 w32dist check check-w32
.PHONY: deinstall uninstall install version
