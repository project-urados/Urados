# Top-level build for Urados. Builds the package manager and init system so
# that nothing has to be compiled from inside a subdirectory.
#
#   make              build the package manager and Uinit
#   make pkg_mgr      build only urpkg and urdev
#   make uinit        build only Uinit
#   make uinit STATIC_LIB=blkid
#                     statically link Uinit's blkid library and dependencies
#   make test         build, then run the end-to-end suite (needs passwordless
#                     sudo; see pkg_mgr/tests/test_e2e.sh)
#   make install      install urpkg and urdev into $(DESTDIR)$(PREFIX)/bin
#   make clean        remove all package-manager and Uinit build output
#
# Requirements: see pkg_mgr/Makefile and init/Makefile for the dependencies of
# each component. A target only checks the dependencies of the component it
# builds.

PREFIX  ?= /usr/local
DESTDIR ?=

PKG_MGR = pkg_mgr
INIT    = init
TOOLS   = urpkg urdev

all: pkg_mgr uinit

pkg_mgr:
	$(MAKE) -C $(PKG_MGR) all

uinit:
	$(MAKE) -C $(INIT) all

test: pkg_mgr
	$(MAKE) -C $(PKG_MGR) test

install: pkg_mgr
	install -d "$(DESTDIR)$(PREFIX)/bin"
	for t in $(TOOLS); do \
		install -m 0755 "$(PKG_MGR)/build/$$t" "$(DESTDIR)$(PREFIX)/bin/$$t" || exit 1; \
	done

clean:
	$(MAKE) -C $(PKG_MGR) clean
	$(MAKE) -C $(INIT) clean

.PHONY: all pkg_mgr uinit test install clean
