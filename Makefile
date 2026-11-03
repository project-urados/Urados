# Top-level build for Urados. Builds every tool so that nothing has to be
# compiled from inside a subdirectory.
#
#   make              build urpkg, urdev and apprestorecon (in pkg_mgr/build/)
#   make test         build, then run the end-to-end suite (needs passwordless
#                     sudo; see pkg_mgr/tests/test_e2e.sh)
#   make install      install the tools into $(DESTDIR)$(PREFIX)/bin
#                     (PREFIX defaults to /usr/local)
#   make clean        remove all build output
#
# Requirements: gcc, pkg-config, and the development files for libxml-2.0,
# libzip, libcurl, OpenSSL 3, libselinux and libsemanage.

PREFIX  ?= /usr/local
DESTDIR ?=

PKG_MGR = pkg_mgr
TOOLS   = urpkg urdev apprestorecon

all:
	$(MAKE) -C $(PKG_MGR) all

test: all
	$(MAKE) -C $(PKG_MGR) test

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin"
	for t in $(TOOLS); do \
		install -m 0755 "$(PKG_MGR)/build/$$t" "$(DESTDIR)$(PREFIX)/bin/$$t" || exit 1; \
	done

clean:
	$(MAKE) -C $(PKG_MGR) clean

.PHONY: all test install clean
