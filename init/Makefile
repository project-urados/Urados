# uinit: the Urados init system. Runs as PID 1, or standalone with --root.
#
#   make              build build/uinit
#   make test         build, then run the unit tests (the mount tests need
#                     passwordless sudo and loop devices)
#   make check-example run uinit --check against examples/root
#   make clean        remove build output
#
# Requirements: gcc, pkg-config, and the development files for libblkid
# (util-linux, package libblkid-dev / libblkid-devel).

CC     ?= cc
CFLAGS ?= -O2 -g
PKG_CONFIG ?= pkg-config
DEPS    = blkid
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
          $(shell $(PKG_CONFIG) --cflags $(DEPS) 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs $(DEPS) 2>/dev/null)

BUILD = build
HDRS  = include/uinit.h
SRCS  = src/main.c src/util.c src/config.c src/parse.c src/run.c src/exec.c src/mount.c

all: check-deps $(BUILD)/uinit

check-deps:
	@command -v "$(PKG_CONFIG)" >/dev/null 2>&1 || { \
		echo "uinit build error: pkg-config is required" >&2; exit 1; \
	}
	@$(PKG_CONFIG) --exists $(DEPS) || { \
		echo "uinit build error: libblkid development files are missing" >&2; \
		echo "  Debian/Ubuntu: sudo apt install libblkid-dev" >&2; \
		echo "  Fedora/RHEL:   sudo dnf install libblkid-devel" >&2; \
		exit 1; \
	}

$(BUILD)/uinit: check-deps $(SRCS) $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

$(BUILD):
	mkdir -p $@

$(BUILD)/test_parse: check-deps $(SRCS) $(HDRS) tests/test_parse.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/util.c src/config.c src/parse.c src/mount.c tests/test_parse.c $(LDLIBS)

test: all $(BUILD)/test_parse
	$(BUILD)/test_parse
	sh tests/test_uinit.sh

check-example: all
	$(BUILD)/uinit --root examples/root --check -v

clean:
	rm -rf $(BUILD) 2>/dev/null || sudo -n rm -rf $(BUILD)

.PHONY: all check-deps test check-example clean
