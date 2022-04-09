# see LICENSE for copyright and license details
PREFIX = /usr/local
CC = cc
CFLAGS ?= -O0 -g -Wall -Wextra
CFLAGS += $(shell pkg-config --cflags libcurl libssl libcrypto)
LDFLAGS ?=
LDFLAGS += $(shell pkg-config --libs libcurl libssl libcrypto)
OBJ = bestline/bestline.o gplaces.o
BIN = gplaces
CONF = gplaces.conf

default: $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

.PHONY: clean
clean:
	@rm -f $(BIN) $(OBJ)

install: default
	@mkdir -p $(DESTDIR)$(PREFIX)/bin/
	@install $(BIN) $(DESTDIR)$(PREFIX)/bin/${BIN}
	@mkdir -p $(DESTDIR)$(PREFIX)/etc
	@install $(CONF) $(DESTDIR)$(PREFIX)/etc/${CONF}

uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@rm -f $(DESTDIR)$(PREFIX)/etc/$(CONF)
