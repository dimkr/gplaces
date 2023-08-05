# see LICENSE for copyright and license details
PREFIX = /usr/local
CONFDIR ?= $(PREFIX)/etc
CC = cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-result
VERSION ?= $(shell git describe --tags 2>/dev/null | sed s/^v//)
ifeq ($(VERSION),)
	VERSION = ?
endif
CFLAGS += -D_GNU_SOURCE  -DPREFIX=\"$(PREFIX)\" -DCONFDIR=\"$(CONFDIR)\" -DGPLACES_VERSION=\"$(VERSION)\" $(shell pkg-config --cflags libcurl libssl libcrypto)
LDFLAGS ?=
LDFLAGS += $(shell pkg-config --libs libcurl libssl libcrypto)
MIMETYPES =
WITH_GOPHER ?= 1
ifeq ($(WITH_GOPHER),1)
	CFLAGS += -DGPLACES_WITH_GOPHER
	MIMETYPES := $(MIMETYPES);x-scheme-handler/gopher
endif
WITH_GOPHERS ?= 1
ifeq ($(WITH_GOPHERS),1)
	CFLAGS += -DGPLACES_WITH_GOPHERS
	MIMETYPES := $(MIMETYPES);x-scheme-handler/gophers
endif
WITH_SPARTAN ?= 1
ifeq ($(WITH_SPARTAN),1)
	CFLAGS += -DGPLACES_WITH_SPARTAN
	MIMETYPES := $(MIMETYPES);x-scheme-handler/spartan
endif
WITH_FINGER ?= 1
ifeq ($(WITH_FINGER),1)
	CFLAGS += -DGPLACES_WITH_FINGER
	MIMETYPES := $(MIMETYPES);x-scheme-handler/finger
endif
WITH_GUPPY ?= 1
ifeq ($(WITH_GUPPY),1)
	CFLAGS += -DGPLACES_WITH_GUPPY
	MIMETYPES := $(MIMETYPES);x-scheme-handler/guppy
endif
WITH_LIBIDN2 ?= $(shell pkg-config --exists libidn2 && echo 1 || echo 0)
ifeq ($(WITH_LIBIDN2),1)
	CFLAGS += -DGPLACES_USE_LIBIDN2 $(shell pkg-config --cflags libidn2)
	LDFLAGS += $(shell pkg-config --libs libidn2)
else
	WITH_LIBIDN ?= $(shell pkg-config --exists libidn && echo 1 || echo 0)
	ifeq ($(WITH_LIBIDN),1)
		CFLAGS += -DGPLACES_USE_LIBIDN $(shell pkg-config --cflags libidn)
		LDFLAGS += $(shell pkg-config --libs libidn)
	endif
endif
WITH_LIBMAGIC ?= $(shell pkg-config --exists libmagic && echo 1 || echo 0)
ifeq ($(WITH_LIBMAGIC),1)
	CFLAGS += -DGPLACES_USE_LIBMAGIC $(shell pkg-config --cflags libmagic)
	LDFLAGS += $(shell pkg-config --libs libmagic)
endif
ifeq ($(WITH_FLATPAK_SPAWN),1)
	CFLAGS += -DGPLACES_USE_FLATPAK_SPAWN
endif
OBJ = bestline/bestline.o gplaces.o
BIN = gplaces

all: $(BIN) gplacesrc gplaces.desktop

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

gplaces.o: gplaces.c gopher.c gophers.c spartan.c finger.c guppy.c socket.c

gplaces.desktop: gplaces.desktop.in
	@sed "s~^MimeType=.*~&$(MIMETYPES)~" $< > $@

gplacesrc: gplacesrc.in
	sed s~DOCDIR~$(PREFIX)/share/doc/gplaces~g $^ > $@

.PHONY: clean
clean:
	@rm -f $(BIN) $(OBJ) gplacesrc gplaces.desktop

install: all
	@install -D -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/${BIN}
	@install -D -m 644 gplacesrc $(DESTDIR)$(CONFDIR)/gplacesrc
	@install -D -m 644 README.md $(DESTDIR)$(PREFIX)/share/doc/gplaces/README.gmi
	@install -m 644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/gplaces/LICENSE
	@install -m 644 AUTHORS $(DESTDIR)$(PREFIX)/share/doc/gplaces/AUTHORS
	@install -D -m 644 gplaces.1 $(DESTDIR)$(PREFIX)/share/man/man1/gplaces.1
	@install -D -m 644 gplaces.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/gplaces.svg
	@install -D -m 644 gplaces.desktop $(DESTDIR)$(PREFIX)/share/applications/gplaces.desktop
	@install -D -m 644 com.github.dimkr.gplaces.appdata.xml $(DESTDIR)$(PREFIX)/share/metainfo/com.github.dimkr.gplaces.appdata.xml

uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@rm -f $(DESTDIR)$(CONFDIR)/gplacesrc
	@rm -rf $(DESTDIR)$(PREFIX)/share/doc/gplaces
	@rm -f $(DESTDIR)$(PREFIX)/share/man/man1/gplaces.1
	@rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/gplaces.svg
	@rm -f $(DESTDIR)$(PREFIX)/share/applications/gplaces.desktop
	@rm -f $(DESTDIR)$(PREFIX)/share/metainfo/com.github.dimkr.gplaces.appdata.xml
