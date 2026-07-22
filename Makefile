# Makefile for libdoorman + CLI + example + tests.
#
# This is the plain (non-Nix) build used by CI and by anyone consuming the
# framework normally. It builds for the host architecture (arm64 on Apple
# Silicon); flake.nix builds universal (arm64 + x86_64) binaries, which is
# what tagged releases ship.
#
# Targets:
#   make            build the library, CLI, example, and tests
#   make lib        build libdoorman.a and libdoorman.dylib
#   make cli        build the doorman CLI (+ Linux-tool symlinks)
#   make example    build the macdm example
#   make test       build and run the (unprivileged) unit tests
#   make install    install lib/headers/bin into $(PREFIX) (default /usr/local)
#   make clean

CC        ?= xcrun clang
ARCH      ?= $(shell uname -m)
PREFIX    ?= /usr/local

BUILD     := build
OBJ       := $(BUILD)/obj
LIBDIR    := $(BUILD)/lib
BINDIR    := $(BUILD)/bin

# Strict, warnings-as-errors. This is the same set CI enforces; the library is
# expected to build clean under all of it.
STRICT    := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
             -Wcast-qual -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
             -Wformat=2 -Wundef -Wvla -Werror

# -fvisibility=hidden keeps every internal (_dm_*) symbol out of the dynamic
# symbol table; only the doorman_* API (marked default in the header) is
# exported. Smaller dylib, faster dyld binding, more room to inline.
CFLAGS    := -arch $(ARCH) -O2 -fvisibility=hidden $(STRICT) -Idoorman/include
# Objective-C translation units are built under ARC; the pure-C example is not.
OBJCARC   := -fobjc-arc
LDFRAME   := -framework Foundation -framework OpenDirectory -framework Security
LDLIBS    := -lpam -lobjc

LIB_SRCS  := $(wildcard doorman/src/*.m)
LIB_OBJS  := $(patsubst doorman/src/%.m,$(OBJ)/%.o,$(LIB_SRCS))

STATICLIB := $(LIBDIR)/libdoorman.a
DYLIB     := $(LIBDIR)/libdoorman.dylib

TOOLLINKS := useradd userdel passwd groupadd groupdel usermod gpasswd

.PHONY: all lib cli example test install clean
all: lib cli example tests

$(OBJ)/%.o: doorman/src/%.m | $(OBJ)
	$(CC) $(CFLAGS) $(OBJCARC) -c $< -o $@

$(OBJ) $(LIBDIR) $(BINDIR):
	@mkdir -p $@

lib: $(STATICLIB) $(DYLIB)

$(STATICLIB): $(LIB_OBJS) | $(LIBDIR)
	xcrun ar rcs $@ $(LIB_OBJS)

$(DYLIB): $(LIB_OBJS) | $(LIBDIR)
	$(CC) $(CFLAGS) $(OBJCARC) -dynamiclib -install_name @rpath/libdoorman.dylib \
		$(LIB_OBJS) $(LDFRAME) $(LDLIBS) -o $@

cli: $(BINDIR)/doorman
$(BINDIR)/doorman: cli/doorman.m $(STATICLIB) | $(BINDIR)
	$(CC) $(CFLAGS) $(OBJCARC) $< $(STATICLIB) $(LDFRAME) $(LDLIBS) -o $@
	@for t in $(TOOLLINKS); do ln -sf doorman $(BINDIR)/$$t; done

example: $(BINDIR)/macdm
$(BINDIR)/macdm: examples/macdm/macdm.c $(STATICLIB) | $(BINDIR)
	$(CC) $(CFLAGS) $< $(STATICLIB) $(LDFRAME) $(LDLIBS) -o $@

tests: $(BINDIR)/test_doorman
$(BINDIR)/test_doorman: tests/test_doorman.m $(STATICLIB) | $(BINDIR)
	$(CC) $(CFLAGS) $(OBJCARC) $< $(STATICLIB) $(LDFRAME) $(LDLIBS) -o $@

test: tests
	@echo "== unit tests =="
	$(BINDIR)/test_doorman

install: all
	@install -d $(PREFIX)/lib $(PREFIX)/include $(PREFIX)/bin $(PREFIX)/share/doc/doorman
	install -m 0644 $(STATICLIB) $(PREFIX)/lib/
	install -m 0755 $(DYLIB) $(PREFIX)/lib/
	install -m 0644 doorman/include/doorman.h $(PREFIX)/include/
	install -m 0755 $(BINDIR)/doorman $(PREFIX)/bin/
	install -m 0644 LICENSE $(PREFIX)/share/doc/doorman/LICENSE
	@for t in $(TOOLLINKS); do ln -sf doorman $(PREFIX)/bin/$$t; done

clean:
	rm -rf $(BUILD)
