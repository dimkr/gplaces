/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2022, 2023  Dima Krasner

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

================================================================================
*/
#include <poll.h>


typedef struct GuppySocket {
	int fd; /* must be first so socket_*() work */
	long last;
	struct {
		long seq;
		ssize_t length;
		char buffer[4096];
	} chunks[8];
} GuppySocket;


/*============================================================================*/
static void guppy_close(void *c) {
	socket_close(c);
	free(c);
}


static int guppy_ack(int fd, long seq) {
	char ack[12];
	int length;
	ssize_t sent;

	length = sprintf(ack, "%ld\r\n", seq);

	if ((sent = send(fd, ack, length, 0)) < 0) return 0;
	if (sent != (ssize_t)length) { errno = EPROTO; return 0; }

	return 1;
}


static int do_guppy_download(URL *url, GuppySocket *s, char **mime, int ask) {
	static char buffer[1024], prompt[1024];
	struct pollfd pfd = {.events = POLLIN};
	char *crlf, *end, *input;
	ssize_t j = -1;
	int len, timeout, i, n;

	if ((len = strlen(url->url)) > (int)sizeof(buffer) - 2) goto fail;

	if ((s->fd = pfd.fd = socket_connect(url, SOCK_DGRAM)) == -1) goto fail;

	memcpy(buffer, url->url, len);
	buffer[len] = '\r';
	buffer[len + 1] = '\n';

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;

	for (i = 0; i < timeout; ++i) {
request:
		/* send or re-transmit the request */
		if (send(pfd.fd, buffer, len + 2, 0) <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
			else error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
			goto fail;
		}

		pfd.revents = 0;
		if ((n = poll(&pfd, 1, 1000)) == 0) continue;
		if (n < 0 || (n > 0 && !(pfd.revents & POLLIN))) goto fail;

		while (1) {
			j = (j == sizeof(s->chunks) / sizeof(s->chunks[0]) - 1) ? 0 : j + 1;

			if ((s->chunks[j].length = recv(pfd.fd, s->chunks[j].buffer, sizeof(s->chunks[j].buffer), MSG_DONTWAIT)) < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) goto request;
				error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
				goto fail;
			}

			if (s->chunks[j].length < 5 || (crlf = memchr(s->chunks[j].buffer, '\r', s->chunks[j].length - 1)) == NULL || *(crlf + 1) != '\n') continue;

			*crlf = '\0';

			if (s->chunks[j].buffer[0] == '1' && s->chunks[j].buffer[1] == ' ') {
				if (!ask) goto fail;
				if (color) snprintf(prompt, sizeof(prompt), "\33[35m%.*s>\33[0m ", get_terminal_width() - 2, &s->chunks[j].buffer[2]);
				else snprintf(prompt, sizeof(prompt), "%.*s> ", get_terminal_width() - 2, &s->chunks[j].buffer[2]);
				if ((input = bestline(prompt)) == NULL) goto fail;
				if (interactive) bestlineHistoryAdd(input);
				if (!set_input(url, input)) { free(input); goto fail; }
				free(input);
				if (interactive) bestlineHistoryAdd(url->url);
				close(s->fd);
				s->fd = -1;
				return 1;
			} else if (s->chunks[j].buffer[0] == '3' && s->chunks[j].buffer[1] == ' ') {
				if (!redirect(url, &s->chunks[j].buffer[2], s->chunks[j].length - 4, ask)) goto fail;
				close(s->fd);
				s->fd = -1;
				return 3;
			} else if (s->chunks[j].buffer[0] == '4' && s->chunks[j].buffer[1] == ' ') {
				error(0, "cannot download `%s`: %s", url->url, &s->chunks[j].buffer[2]);
				goto fail;
			}

			s->chunks[j].seq = strtol(s->chunks[j].buffer, &end, 10);
			if (s->chunks[j].seq < 6 || s->chunks[j].seq == LONG_MAX) { s->chunks[j].seq = -1; continue; }
			if (s->chunks[j].seq > INT_MAX || end == NULL || (*end != ' ' && *end != '\r')) { s->chunks[j].seq = -1; continue; }
			if (*end != ' ') { *crlf = '\r'; continue; }

			*crlf = '\r';
			*mime = end + 1;

			return 2;
		}
	}

	error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);

fail:
	close(s->fd);
	s->fd = -1;
	return -1;
}


static void *guppy_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	GuppySocket *s = NULL;
	size_t i;
	int status, redirs = 0;

	(void)sel;

	if ((s = malloc(sizeof(GuppySocket))) == NULL) return NULL;
	s->fd = s->last = -1;
	for (i = 0; i < sizeof(s->chunks) / sizeof(s->chunks[0]); ++i) s->chunks[i].seq = -1;

	do {
		status = do_guppy_download(url, s, mime, ask);
		/* stop on success, on error or when the redirect limit is exhausted */
		if (status > 5) break;
	} while (((status == 1) || (status == 3)) && ++redirs < 5);

	if (s->fd != -1 && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (s->fd != -1 && strncmp(*mime, "text/plain", 10) == 0) *parser = parse_plaintext_line;

	if (redirs == 5) error(0, "too many redirects from `%s`", url->url);

	if (s->fd == -1) { free(s); return NULL; }
	return s;
}


static int guppy_read(void *c, void *buffer, int length) {
	GuppySocket *s = (GuppySocket*)c;
	struct pollfd pfd = {.fd = s->fd, .events = POLLIN};
	int skip;
	char *crlf, *end;
	size_t i;
	int timeout, j, n, ret;

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;

	do {
		/* check if we have the packet already */
		for (i = 0; i < sizeof(s->chunks) / sizeof(s->chunks[0]); ++i) {
			if ((s->last == -1 && s->chunks[i].seq != -1) || s->chunks[i].seq == s->last + 1) goto parse;
		}

		/* find a free slot */
		for (i = 0; i < sizeof(s->chunks) / sizeof(s->chunks[0]); ++i) {
			if (s->chunks[i].seq <= s->last) goto wait;
		}

		/* use the first slot if all slots are used and we don't have the packet */
		i = 0;

wait:
		for (j = 0; j < timeout; ++j) {
			/* wait for the response packet and resend ack for the previous packet on timeout */
			pfd.revents = 0;
			if ((n = poll(&pfd, 1, 1000)) == 0 && s->last != -1 && !guppy_ack(s->fd, s->last)) return -1;
			if (n < 0 || (n > 0 && !(pfd.revents & POLLIN))) return -1;
			if (n > 0) goto receive;
		}

		errno = ETIMEDOUT;
		return -1;

receive:
		/* receive a packet */
		if ((s->chunks[i].length = recv(s->fd, s->chunks[i].buffer, sizeof(s->chunks[i].buffer), 0)) < 0) return -1;
		if (s->chunks[i].length == 0) { errno = ECONNRESET; return 0; }

parse:
		/* extract the sequence number */
		if ((crlf = memchr(s->chunks[i].buffer, '\r', s->chunks[i].length - 1)) == NULL || crlf == s->chunks[i].buffer || *(crlf + 1) != '\n') { errno = EPROTO; return -1; }
		*crlf = '\0';
		if ((s->chunks[i].seq = strtol(s->chunks[i].buffer, &end, 10)) == LONG_MIN || s->chunks[i].seq == LONG_MAX) { *crlf = '\r'; s->chunks[i].seq = -1; return -1; }
		if (s->chunks[i].seq > INT_MAX || end == NULL || (*end != ' ' && *end != '\0')) { errno = EPROTO; return -1; }
		skip = crlf - s->chunks[i].buffer + 2;
		*crlf = '\r';
	} while (s->last != -1 && s->chunks[i].seq != s->last + 1); /* repeat until we have the next packet */

	/* ack the packet */
	if (!guppy_ack(s->fd, s->chunks[i].seq)) return -1;

	/* signal EOF if this is the EOF packet */
	if (skip == s->chunks[i].length) return 0;

	s->last = s->chunks[i].seq;
	ret = (length > s->chunks[i].length - skip ? s->chunks[i].length - skip : length);
	memmove(buffer, crlf + 2, ret);
	return ret;
}


const Protocol guppy = {"guppy", "6775", guppy_read, NULL, socket_error, guppy_close, guppy_download};
