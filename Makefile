CXX ?= c++
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Iinclude $(shell $(PKG_CONFIG) --cflags libxml-2.0 openssl liblzma zlib icu-uc)
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
LDLIBS += $(shell $(PKG_CONFIG) --libs libxml-2.0 openssl liblzma zlib icu-uc)
ifeq ($(shell uname -s),Linux)
LDLIBS += -ldl
endif
CORE = src/common.cpp src/platform.cpp src/windows.cpp src/pe.cpp src/backing.cpp src/dump.cpp
LEGACY = src/rsp.cpp src/legacy.cpp
HEADERS = $(wildcard include/qpd/*.hpp)

.PHONY: all check test sanitize integration clean
all: bin/qemu-process-dumper

bin/qemu-process-dumper: $(CORE) src/main.cpp $(LEGACY) $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CORE) src/main.cpp $(LEGACY) $(LDFLAGS) $(LDLIBS) -o $@

check:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fsyntax-only $(CORE) src/main.cpp $(LEGACY)

bin/unit-tests: $(CORE) src/rsp.cpp tests/unit.cpp $(HEADERS)
	@mkdir -p bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CORE) src/rsp.cpp tests/unit.cpp $(LDFLAGS) $(LDLIBS) -o $@

test: bin/unit-tests
	./bin/unit-tests

sanitize:
	$(MAKE) test CXXFLAGS='-std=c++20 -O1 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' -B

integration: bin/qemu-process-dumper
	python3 tests/integration.py

clean:
	rm -rf bin
