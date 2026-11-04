# Use with: make -f Makefile -f audit.mk build/native-audit build/analysis-lockdown.so
build/native-audit: native_audit.cpp native.hpp core.hpp build/libsleigh.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) native_audit.cpp build/libsleigh.a \
	 -L$(Z3_ROOT)/lib -Wl,-rpath,'$$ORIGIN/../.deps/z3/lib' -lz3 $(ZLIB_LIB) -o $@

build/analysis-lockdown.so: analysis_lockdown.c
	@mkdir -p build
	$(CC) -shared -fPIC -O2 -Wall -Wextra $< -o $@
