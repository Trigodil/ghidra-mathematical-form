CXX ?= g++
CC ?= gcc
GHIDRA_SRC := ../../../Ghidra/Features/Decompiler/src/decompile/cpp
Z3_ROOT ?= .deps/z3
ZLIB_INCLUDE ?= .deps/zlib
ZLIB_LIB ?= -l:libz.so.1
SLA_FILE ?= .deps/spec/x86-64.sla
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter
CPPFLAGS += -isystem $(GHIDRA_SRC) -isystem $(Z3_ROOT)/include -I$(ZLIB_INCLUDE)
SLEIGH_SOURCES := xml marshal space float address pcoderaw translate opcodes metatype globalcontext \
 sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics \
 context slaformat compression filemanage loadimage
SLEIGH_OBJECTS := $(addprefix build/sleigh/,$(addsuffix .o,$(SLEIGH_SOURCES)))

.PHONY: all run check inverse-check state-check clean
all: build/graph-fibers build/fixtures.so

build/sleigh/%.o: $(GHIDRA_SRC)/%.cc
	@mkdir -p build/sleigh
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

build/libsleigh.a: $(SLEIGH_OBJECTS)
	ar rcs $@ $^

build/graph-fibers: main.cpp core.hpp native.hpp inverse.hpp dimensions.hpp build/libsleigh.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main.cpp build/libsleigh.a \
	 -L$(Z3_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../.deps/z3/lib' -lz3 $(ZLIB_LIB) -ldl -o $@

build/fixtures.so: ../fixtures.c
	@mkdir -p build
	$(CC) -O2 -shared -fPIC -fcf-protection=none -fno-if-conversion -fno-if-conversion2 $< -o $@

build/loop_fixtures.so: loop_fixtures.c
	@mkdir -p build
	$(CC) -O2 -shared -fPIC -fcf-protection=none -fno-if-conversion -fno-if-conversion2 \
	 -fno-tree-loop-optimize -fno-tree-vectorize -fno-unroll-loops $< -o $@

build/state-loop: state_main.cpp synthesis.hpp loop_proof.hpp inverse.hpp native.hpp core.hpp build/libsleigh.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) state_main.cpp build/libsleigh.a \
	 -L$(Z3_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../.deps/z3/lib' -lz3 $(ZLIB_LIB) -ldl -o $@

build/benchmark: benchmark.cpp synthesis.hpp inverse.hpp native.hpp core.hpp build/libsleigh.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) benchmark.cpp build/libsleigh.a \
	 -L$(Z3_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../.deps/z3/lib' -lz3 $(ZLIB_LIB) -ldl -o $@

build/abi-summary: abi_summary.cpp inverse.hpp native.hpp core.hpp build/libsleigh.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) abi_summary.cpp build/libsleigh.a \
	 -L$(Z3_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../.deps/z3/lib' -lz3 $(ZLIB_LIB) -o $@

run check: all
	./build/graph-fibers --sla $(SLA_FILE) --fixtures ./build/fixtures.so --output ./build/results

inverse-check: all
	./build/graph-fibers --sla $(SLA_FILE) --inverse-fixtures ./build/fixtures.so --output ./build/inverse-results

state-check: build/state-loop build/fixtures.so build/loop_fixtures.so
	./build/state-loop --sla $(SLA_FILE) --fixtures build/fixtures.so --loops build/loop_fixtures.so --output build/state-results

clean:
	$(RM) -r build

-include $(SLEIGH_OBJECTS:.o=.d)
