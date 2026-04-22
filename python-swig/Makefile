# SWIG python bindings for radare2 — no valabind dependency.
#
# Pipeline per module:
#   r_core.i --(swig)--> r_core_wrap.cxx + r_core.py --(c++)--> _r_core.<ext>
#
# Requirements: swig, python3, a pkg-config-discoverable radare2 install.

SWIG        ?= swig
PYTHON      ?= python3
PYTHON_CONFIG ?= python3-config
PKG_CONFIG  ?= pkg-config

MODULES     := r_core

UNAME_S     := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  SOEXT     := dylib
  SHFLAGS   := -dynamiclib -undefined dynamic_lookup
else
  SOEXT     := so
  SHFLAGS   := -shared
endif

# Python C extension suffix (e.g. .cpython-314-darwin.so). Used for importable name.
PYEXT_SUFFIX := $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')

PY_CFLAGS   := $(shell $(PYTHON_CONFIG) --cflags | sed 's/-arch [^ ]*//g')
PY_LDFLAGS  := $(shell $(PYTHON_CONFIG) --ldflags | sed 's/-arch [^ ]*//g')

R2_CFLAGS   := $(shell $(PKG_CONFIG) --cflags r_core)
R2_LIBS     := $(shell $(PKG_CONFIG) --libs   r_core)

SWIG_FLAGS  := -python -c++ -O
CXXFLAGS    += -fPIC -O2 -Wno-deprecated-declarations

WRAPPERS    := $(addsuffix _wrap.cxx,$(MODULES))
PY_MODS     := $(addsuffix .py,$(MODULES))
SO_MODS     := $(addprefix _,$(addsuffix $(PYEXT_SUFFIX),$(MODULES)))

all: $(SO_MODS)

# SWIG: .i -> _wrap.cxx + .py
%_wrap.cxx %.py: %.i
	$(SWIG) $(SWIG_FLAGS) $(R2_CFLAGS) -o $*_wrap.cxx $<

# C++: _wrap.cxx -> _<module><pyext>
_%$(PYEXT_SUFFIX): %_wrap.cxx
	$(CXX) $(CXXFLAGS) $(SHFLAGS) $(PY_CFLAGS) $(R2_CFLAGS) \
		$< -o $@ $(R2_LIBS) $(PY_LDFLAGS)

test: all
	PYTHONPATH=. $(PYTHON) test.py

clean:
	rm -f $(WRAPPERS) $(PY_MODS) $(SO_MODS) _*.$(SOEXT)
	rm -rf __pycache__

.PHONY: all test clean
