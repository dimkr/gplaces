# see LICENSE for copyright and license details
PREFIX = /usr/local
CONFDIR ?= $(PREFIX)/etc
MANDIR = $(PREFIX)/share/man
ICONDIR = $(PREFIX)/share/icons
APPDIR = $(PREFIX)/share/applications
CC = cc
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -DCONFDIR=\"$(CONFDIR)\" $(shell pkg-config --cflags libcurl)
LDFLAGS ?=
LDFLAGS += $(shell pkg-config --libs libcurl)
WITH_MBEDTLS ?= 0
ifeq ($(WITH_MBEDTLS),1)
	CFLAGS += -DGPLACES_USE_MBEDTLS
	LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
else
	CFLAGS += $(shell pkg-config --cflags libssl libcrypto)
	LDFLAGS += $(shell pkg-config --libs libssl libcrypto)
endif
WITH_LIBMAGIC ?= $(shell pkg-config --exists libmagic && echo 1 || echo 0)
ifeq ($(WITH_LIBMAGIC),1)
	CFLAGS += -DGPLACES_USE_LIBMAGIC $(shell pkg-config --cflags libmagic)
	LDFLAGS += $(shell pkg-config --libs libmagic)
endif
OBJ = bestline/bestline.o gplaces.o
BIN = gplaces
CONF = gplaces.conf
MAN = gplaces.1
ICON = gplaces.svg
APP = gplaces.desktop

default: $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

.PHONY: clean
clean:
	@rm -f $(BIN) $(OBJ)

install: default
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

uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@rm -f $(DESTDIR)$(CONFDIR)/$(CONF)
	@rm -f $(DESTDIR)$(MANDIR)/man1/${MAN}
	@rm -f $(DESTDIR)$(ICONDIR)/hicolor/scalable/apps/${ICON}
	@rm -f $(DESTDIR)$(APPDIR)/${APP}
