# Urados package tools: urpkg (package manager) and urdev (developer tool).
#
# Requires gcc, pkg-config, and development files for libxml-2.0, libzip,
# libcurl and OpenSSL 3. E2E tests also need passwordless sudo.
#
#   make        build build/urpkg and build/urdev
#   make STATIC=1
#               statically link the complete package manager and dependencies
#   make STATIC_LIB=libxml-2.0
#               statically link only libxml-2.0
#   make test   build, run certificate tests, then end-to-end tests (the latter
#               need passwordless sudo)

CC     ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
DEPS    = libxml-2.0 libzip libcurl libcrypto
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
          $(shell $(PKG_CONFIG) --cflags $(DEPS) 2>/dev/null)

# Local build options. STATIC=1 makes the complete executable static and uses
# every transitive library from `pkg-config --libs --static $(DEPS)`. For a
# partial link, STATIC_LIB forces only the selected module's first -l library
# flag static while all other package-manager libraries remain dynamic. The
# options are intentionally local to this Makefile and are not repository-wide.
STATIC ?=
STATIC_LIB ?=
ifneq ($(strip $(STATIC)),)
ifneq ($(strip $(STATIC_LIB)),)
$(error STATIC and STATIC_LIB cannot be used together)
endif
LDFLAGS += -static
STATIC_LDLIBS := $(shell $(PKG_CONFIG) --libs --static $(DEPS) 2>/dev/null)
LDLIBS += $(STATIC_LDLIBS)
else ifeq ($(strip $(STATIC_LIB)),)
LDLIBS += $(shell $(PKG_CONFIG) --libs $(DEPS) 2>/dev/null)
else
STATIC_LDLIB := $(word 1,$(shell $(PKG_CONFIG) --libs-only-l --static $(STATIC_LIB) 2>/dev/null))
NORMAL_LDLIBS := $(shell $(PKG_CONFIG) --libs $(DEPS) 2>/dev/null)
LDLIBS += $(filter-out $(STATIC_LDLIB),$(NORMAL_LDLIBS)) \
          -Wl,-Bstatic $(STATIC_LDLIB) -Wl,-Bdynamic
endif

BUILD  = build
HDRS   = include/urados_pkg.h
COMMON = src/common.c src/crypto.c src/manifest.c src/meta_files.c src/sys.c src/archive.c src/fetch.c

all: check-deps $(BUILD)/urpkg $(BUILD)/urdev

check-deps:
	@command -v "$(PKG_CONFIG)" >/dev/null 2>&1 || { \
		echo "Urados build error: pkg-config is required" >&2; exit 1; \
	}
	@$(PKG_CONFIG) --exists $(DEPS) || { \
		echo "Urados build error: required development packages are missing:" >&2; \
		$(PKG_CONFIG) --print-errors --exists $(DEPS) || true; \
		echo "See docs/BUILD.md for installation commands." >&2; exit 1; \
	}
	@if test -n "$(STATIC)" && test -z "$(STATIC_LDLIBS)"; then \
		echo "Urados build error: pkg-config returned no static link flags for the package-manager dependencies" >&2; \
		exit 1; \
	fi
	@if test -n "$(STATIC_LIB)" && test -z "$(STATIC_LDLIB)"; then \
		echo "Urados build error: pkg-config module '$(STATIC_LIB)' has no static library flag" >&2; \
		exit 1; \
	fi

$(BUILD)/urpkg: check-deps $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/urdev: check-deps $(COMMON) src/pack.c src/urdev_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON) src/pack.c src/urdev_main.c $(LDLIBS)

$(BUILD)/urpkg_small_limit: check-deps $(COMMON) src/install.c src/urpkg_main.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) src/install.c src/urpkg_main.c $(LDLIBS)

$(BUILD)/test_extract_limit: check-deps $(COMMON) tests/test_extract_limit.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -DPKG_UNPACKED_MAX=65536 -o $@ $(COMMON) tests/test_extract_limit.c $(LDLIBS)

$(BUILD):
	mkdir -p $@

test: all $(BUILD)/urpkg_small_limit $(BUILD)/test_extract_limit
	sh tests/test_cert.sh
	sh tests/test_e2e.sh

clean:
	rm -rf $(BUILD) 2>/dev/null || sudo -n rm -rf $(BUILD)

.PHONY: all check-deps test clean
