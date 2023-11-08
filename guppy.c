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
	long first, last;
	struct {
		long seq;
		ssize_t length, skip;
		char buffer[4096];
	} chunks[8];
} GuppySocket;


/*============================================================================*/
static void guppy_close(void *c) {
	close(((GuppySocket *)c)->fd);
	free(c);
}


static int guppy_ack(int fd, long seq) {
	char ack[23];
	int length;
	ssize_t sent;

	length = sprintf(ack, "%ld\r\n", seq);

	if ((sent = send(fd, ack, length, 0)) < 0) return 0;
	if (sent != (ssize_t)length) { errno = EPROTO; return 0; }

	return 1;
}


static int do_guppy_download(URL *url, GuppySocket *s, char **mime, int ask) {
	static char buffer[1024], prompt[1024];
	struct pollfd pfd = {.fd = s->fd, .events = POLLIN};
	char *crlf, *end, *input;
	ssize_t j = -1;
	int len, timeout, i, n;

	if ((len = strlen(url->url)) > (int)sizeof(buffer) - 2) return 4;

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
			return 4;
		}

		pfd.revents = 0;
		if ((n = poll(&pfd, 1, 1000)) == 0) continue;
		if (n < 0) return 4;

		while (1) {
			j = (j == sizeof(s->chunks) / sizeof(s->chunks[0]) - 1) ? 0 : j + 1;

			if ((s->chunks[j].length = recv(pfd.fd, s->chunks[j].buffer, sizeof(s->chunks[j].buffer) - 1, MSG_DONTWAIT)) < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) goto request;
				error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
				return 4;
			}

			if (s->chunks[j].length < 5 || (crlf = memchr(s->chunks[j].buffer, '\r', s->chunks[j].length - 1)) == NULL || *(crlf + 1) != '\n') continue;
			*crlf = '\0';

			if (s->chunks[j].buffer[1] == ' ') {
				if (s->chunks[j].buffer[0] == '1') {
					if (!ask) return 4;
					if (color) snprintf(prompt, sizeof(prompt), "\33[35m%.*s>\33[0m ", get_terminal_width() - 2, &s->chunks[j].buffer[2]);
					else snprintf(prompt, sizeof(prompt), "%.*s> ", get_terminal_width() - 2, &s->chunks[j].buffer[2]);
					if ((input = bestline(prompt)) == NULL) return 4;
					if (interactive) bestlineHistoryAdd(input);
					if (!set_input(url, input)) { free(input); return 4; }
					free(input);
					if (interactive) bestlineHistoryAdd(url->url);
				} else if (s->chunks[j].buffer[0] == '3') {
					if (!redirect(url, &s->chunks[j].buffer[2], s->chunks[j].length - 4, ask)) return 4;
				} else if (s->chunks[j].buffer[0] == '4') error(0, "cannot download `%s`: %s", url->url, &s->chunks[j].buffer[2]);
				return s->chunks[j].buffer[0] - '0';
			}

			s->chunks[j].seq = strtol(s->chunks[j].buffer, &end, 10);
			if (s->chunks[j].seq < 6 || s->chunks[j].seq > INT_MAX || end == NULL || (*end != ' ' && (*end != '\r' || *(end + 1) != '\n'))) { s->chunks[j].seq = -1; continue; }
			*crlf = '\r';
			s->chunks[j].skip = crlf - s->chunks[j].buffer + 2;

			guppy_ack(s->fd, s->chunks[j].seq);

			if (*end != ' ') continue;

			s->first = s->chunks[j].seq;
			*mime = end + 1;
			return s->chunks[j].seq;
		}
	}

	error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
	return 4;
}


static void *guppy_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	GuppySocket *s = NULL;
	size_t i;
	int status, redirs = 0;

	(void)sel;

	if ((s = malloc(sizeof(GuppySocket))) == NULL) return NULL;
	if ((s->fd = socket_connect(url, SOCK_DGRAM)) == -1) { free(s); return NULL; }
	s->last = -1;
	for (i = 0; i < sizeof(s->chunks) / sizeof(s->chunks[0]); ++i) s->chunks[i].seq = -1;

	do {
		status = do_guppy_download(url, s, mime, ask);
		/* stop on success, on error or when the redirect limit is exhausted */
		if (status > 5) break;
	} while (((status == 1) || (status == 3)) && ++redirs < 5);

	if (status > 6 && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (status > 6 && strncmp(*mime, "text/plain", 10) == 0) *parser = parse_plaintext_line;
	else if (redirs == 5) error(0, "too many redirects from `%s`", url->url);

	if (status <= 6) { close(s->fd); free(s); return NULL; }
	return s;
}


static int guppy_read(void *c, void *buffer, int length) {
	GuppySocket *s = (GuppySocket*)c;
	struct pollfd pfd = {.fd = s->fd, .events = POLLIN};
	char *end;
	size_t j;
	int timeout, i, n, ret;

	/* check if we have the packet already */
	for (j = 0; j < sizeof(s->chunks) / sizeof(s->chunks[0]); ++j) {
		if ((s->last == -1 && s->chunks[j].seq == s->first) || s->chunks[j].seq == s->last + 1) goto have;
	}

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;

	for (i = 0; i < timeout; ++i) {
		while (1) {
			/* find a free slot or just use the first if all slots are used and we don't have the next chunk */
			for (j = 0; j < sizeof(s->chunks) / sizeof(s->chunks[0]) && s->chunks[j].seq > s->last; ++j);
			if (j == sizeof(s->chunks) / sizeof(s->chunks[0])) j = 0;

			if ((s->chunks[j].length = recv(s->fd, s->chunks[j].buffer, sizeof(s->chunks[j].buffer) - 1, MSG_DONTWAIT)) < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) break;
				return -1;
			}
			if (s->chunks[j].length == 0) { errno = ECONNRESET; return 0; }

			/* extract the sequence number */
			s->chunks[j].buffer[s->chunks[j].length] = '\0';
			if ((s->chunks[j].seq = strtol(s->chunks[j].buffer, &end, 10)) < s->first || s->chunks[j].seq > INT_MAX || end == NULL || *end != '\r' || *(end + 1) != '\n') { s->chunks[j].seq = -1; continue; }
			s->chunks[j].skip = end - s->chunks[j].buffer + 2;

			/* ack the packet */
			if (!guppy_ack(s->fd, s->chunks[j].seq)) return -1;

			if (s->last != -1 && s->chunks[j].seq <= s->last) s->chunks[j].seq = -1;
			else if (s->chunks[j].seq == s->last + 1) goto have;
		}

		/* wait for the next chunk and resend ack for the previous on timeout */
		pfd.revents = 0;
		if ((n = poll(&pfd, 1, 1000)) < 0) return -1;
		else if (n == 0 && s->last != -1 && !guppy_ack(s->fd, s->last)) return -1;
		else if (n == 0) continue;
	}

	errno = ETIMEDOUT;
	return -1;

have:
	/* signal EOF if this is the EOF packet */
	if (s->chunks[j].skip == s->chunks[j].length) return 0;

	s->last = s->chunks[j].seq;
	ret = (length > s->chunks[j].length - s->chunks[j].skip ? s->chunks[j].length - s->chunks[j].skip : length);
	memmove(buffer, s->chunks[j].buffer + s->chunks[j].skip, ret);
	return ret;
}


const Protocol guppy = {"guppy", "6775", guppy_read, NULL, socket_error, guppy_close, guppy_download};
