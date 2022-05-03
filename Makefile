# see LICENSE for copyright and license details
PREFIX = /usr/local
CONFDIR ?= $(PREFIX)/etc
MANDIR = $(PREFIX)/share/man
ICONDIR = $(PREFIX)/share/icons
APPDIR = $(PREFIX)/share/applications
APPDATADIR = $(PREFIX)/share/metainfo
CC = cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-result
VERSION ?= $(shell git describe --tags 2>/dev/null | sed s/^v//)
ifeq ($(VERSION),)
	VERSION = ?
endif
CFLAGS += -D_GNU_SOURCE -DCONFDIR=\"$(CONFDIR)\" -DGPLACES_VERSION=\"$(VERSION)\" $(shell pkg-config --cflags libcurl libssl libcrypto)
LDFLAGS ?=
LDFLAGS += $(shell pkg-config --libs libcurl libssl libcrypto)
WITH_LIBMAGIC ?= $(shell pkg-config --exists libmagic && echo 1 || echo 0)
ifeq ($(WITH_LIBMAGIC),1)
	CFLAGS += -DGPLACES_USE_LIBMAGIC $(shell pkg-config --cflags libmagic)
	LDFLAGS += $(shell pkg-config --libs libmagic)
endif
OBJ = bestline/bestline.o gplaces.o
BIN = gplaces
CONF = gplacesrc
MAN = gplaces.1
ICON = gplaces.svg
APP = gplaces.desktop
APPDATA = com.github.dimkr.gplaces.appdata.xml

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

.PHONY: clean
clean:
	@rm -f $(BIN) $(OBJ)

install: $(BIN)
	@mkdir -p $(DESTDIR)$(PREFIX)/bin/
	@install $(BIN) $(DESTDIR)$(PREFIX)/bin/${BIN}
	@mkdir -p $(DESTDIR)$(CONFDIR)
	@install $(CONF) $(DESTDIR)$(CONFDIR)/${CONF}
	@mkdir -p $(DESTDIR)$(MANDIR)/man1
	@install $(MAN) $(DESTDIR)$(MANDIR)/man1/${MAN}
	@mkdir -p $(DESTDIR)$(ICONDIR)/hicolor/scalable/apps
	@install $(ICON) $(DESTDIR)$(ICONDIR)/hicolor/scalable/apps/${ICON}
	@mkdir -p $(DESTDIR)$(APPDIR)
	@install $(APP) $(DESTDIR)$(APPDIR)/${APP}
	@mkdir -p $(DESTDIR)$(APPDATADIR)
	@install $(APPDATA) $(DESTDIR)$(APPDATADIR)/${APPDATA}

uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@rm -f $(DESTDIR)$(CONFDIR)/$(CONF)
	@rm -f $(DESTDIR)$(MANDIR)/man1/${MAN}
	@rm -f $(DESTDIR)$(ICONDIR)/hicolor/scalable/apps/${ICON}
	@rm -f $(DESTDIR)$(APPDIR)/${APP}
	@rm -f $(DESTDIR)$(APPDATADIR)/${APPDATA}
