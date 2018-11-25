LANG=ctypes
LANG_EXT=py
LIBS_PFX=
FORCE_SOEXT=1
MY_SOEXT=py

include ../rules.mk

all:
	rm -rf radare2-ctypes
	mkdir -p radare2-ctypes
	cp r_*.py radare2-ctypes
	cp __init__.py radare2-ctypes
	python setup.py build

dist:
	rm -rf r2
	mkdir -p r2
	:> r2/__init__.py
	cp r_*.py r2
	cp README.md r2

pub: dist
	LC_CTYPE=C python3 setup.py sdist
	twine upload --repository-url https://upload.pypi.org/legacy/ dist/*

clean:
	LC_CTYPE=C python3 setup.py clean
	rm -rf dist radare2-ctypes

.PHONY: dist pub
