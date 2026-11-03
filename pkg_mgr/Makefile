# Urados package tools: urpkg (package manager) and urdev (developer tool).
#
# Requires gcc, pkg-config, and development files for libxml-2.0, libzip,
# libcurl and OpenSSL 3.
#
#   make        build build/urpkg and build/urdev
#   make test   build, run certificate tests, then end-to-end tests (the latter
#               need passwordless sudo and a SELinux policy store)

CC     ?= cc
CFLAGS ?= -O2 -g
DEPS    = libxml-2.0 libzip libcurl libcrypto libselinux libsemanage
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
          $(shell pkg-config --cflags $(DEPS))
LDLIBS += $(shell pkg-config --libs $(DEPS))

BUILD  = build
HDRS   = include/urados_pkg.h
COMMON = src/common.c src/crypto.c src/manifest.c src/sys.c src/archive.c src/fetch.c src/selinux.c

all: $(BUILD)/urpkg $(BUILD)/urdev $(BUILD)/apprestorecon

$(BUILD)/urpkg: $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/urdev: $(COMMON) src/pack.c src/urdev_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/pack.c src/urdev_main.c $(LDLIBS)

$(BUILD)/apprestorecon: $(COMMON) src/apprestorecon_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/apprestorecon_main.c $(LDLIBS)

$(BUILD)/urpkg_small_limit: $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/test_extract_limit: $(COMMON) tests/test_extract_limit.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) tests/test_extract_limit.c $(LDLIBS)

$(BUILD):
	mkdir -p $@

test: all $(BUILD)/urpkg_small_limit $(BUILD)/test_extract_limit
	sh tests/test_cert.sh
	sh tests/test_e2e.sh

clean:
	rm -rf $(BUILD) 2>/dev/null || sudo -n rm -rf $(BUILD)

.PHONY: all test clean
