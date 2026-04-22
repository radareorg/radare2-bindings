# SWIG python bindings for radare2 — no valabind dependency.
#
# Pipeline:
#   r_core.i --(swig)--> r_core_wrap.cxx + r_core.py --(c++)--> _r_core.so
#
# Requirements: swig, python3, a pkg-config-discoverable radare2 install.

SWIG          ?= swig
PYTHON        ?= python3
PYTHON_CONFIG ?= python3-config
PKG_CONFIG    ?= pkg-config

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  SHFLAGS := -dynamiclib -undefined dynamic_lookup
else
  SHFLAGS := -shared
endif

PY_CFLAGS  := $(shell $(PYTHON_CONFIG) --cflags | sed 's/-arch [^ ]*//g')
PY_LDFLAGS := $(shell $(PYTHON_CONFIG) --ldflags | sed 's/-arch [^ ]*//g')

R2_CFLAGS := $(shell $(PKG_CONFIG) --cflags r_core)
R2_LIBS   := $(shell $(PKG_CONFIG) --libs   r_core)

SWIG_FLAGS := -python -c++ -O
CXXFLAGS   += -fPIC -O2 -Wno-deprecated-declarations

all: _r_core.so

r_core_wrap.cxx r_core.py: r_core.i
	$(SWIG) $(SWIG_FLAGS) $(R2_CFLAGS) -o r_core_wrap.cxx $<

_r_core.so: r_core_wrap.cxx
	$(CXX) $(CXXFLAGS) $(SHFLAGS) $(PY_CFLAGS) $(R2_CFLAGS) \
		$< -o $@ $(R2_LIBS) $(PY_LDFLAGS)

test: all
	PYTHONPATH=. $(PYTHON) test.py

clean:
	rm -f r_core_wrap.cxx r_core.py _r_core.so
	rm -rf __pycache__

.PHONY: all test clean
