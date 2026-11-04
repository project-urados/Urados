# Urados package tools: urpkg (package manager) and urdev (developer tool).
#
# Requires gcc, pkg-config, and development files for libxml-2.0, libzip,
# libcurl, OpenSSL 3, libselinux, libsemanage and libacl. Policy builds need the
# SELinux development Makefile; E2E tests also need passwordless sudo and semodule.
#
#   make        build build/urpkg and build/urdev
#   make test   build, run certificate tests, then end-to-end tests (the latter
#               need passwordless sudo and a SELinux policy store)

CC     ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
DEPS    = libxml-2.0 libzip libcurl libcrypto libselinux libsemanage libacl
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
          $(shell $(PKG_CONFIG) --cflags $(DEPS) 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs $(DEPS) 2>/dev/null)

BUILD  = build
HDRS   = include/urados_pkg.h
COMMON = src/common.c src/crypto.c src/manifest.c src/meta_files.c src/sys.c src/archive.c src/fetch.c src/selinux.c

all: check-deps $(BUILD)/urpkg $(BUILD)/urdev $(BUILD)/apprestorecon $(BUILD)/urapp-runner

check-deps:
	@command -v "$(PKG_CONFIG)" >/dev/null 2>&1 || { \
		echo "Urados build error: pkg-config is required" >&2; exit 1; \
	}
	@$(PKG_CONFIG) --exists $(DEPS) || { \
		echo "Urados build error: required development packages are missing:" >&2; \
		$(PKG_CONFIG) --print-errors --exists $(DEPS) || true; \
		echo "See docs/BUILD.md for installation commands." >&2; exit 1; \
	}

$(BUILD)/urpkg: check-deps $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/urdev: check-deps $(COMMON) src/pack.c src/urdev_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/pack.c src/urdev_main.c $(LDLIBS)

$(BUILD)/apprestorecon: check-deps $(COMMON) src/apprestorecon_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(COMMON) src/apprestorecon_main.c $(LDLIBS)

$(BUILD)/urapp-runner: check-deps src/app_runner.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/app_runner.c $(shell pkg-config --libs libselinux)

$(BUILD)/urpkg_small_limit: check-deps $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/test_extract_limit: check-deps $(COMMON) tests/test_extract_limit.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) tests/test_extract_limit.c $(LDLIBS)

$(BUILD):
	mkdir -p $@

test: all $(BUILD)/urpkg_small_limit $(BUILD)/test_extract_limit
	sh tests/test_cert.sh
	sh tests/test_e2e.sh

clean:
	rm -rf $(BUILD) 2>/dev/null || sudo -n rm -rf $(BUILD)

.PHONY: all check-deps test clean
