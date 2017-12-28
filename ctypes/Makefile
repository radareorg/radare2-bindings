LANG=ctypes
LANG_EXT=py
LIBS_PFX=
FORCE_SOEXT=1
MY_SOEXT=py

include ../rules.mk

dist:
	rm -rf r2
	mkdir -p r2
	:> r2/__init__.py
	cp r_*.py r2
	cp README.md r2

pub: dist
	LC_CTYPE=C python3 setup.py sdist upload -r pypi

.PHONY: dist pub
