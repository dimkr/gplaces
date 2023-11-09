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


/*============================================================================*/
typedef struct GuppyChunk {
	long seq;
	ssize_t length, skip;
	char buffer[USHRT_MAX + 1];
	LIST_ENTRY(GuppyChunk) next;
} GuppyChunk;
typedef LIST_HEAD(GuppyChunks, GuppyChunk) GuppyChunks;

typedef struct GuppySocket {
	int fd; /* must be first so socket_*() work */
	GuppyChunks chunks;
	long first, last;
} GuppySocket;


/*============================================================================*/
static void guppy_close(void *c) {
	GuppySocket *s = (GuppySocket *)c;
	GuppyChunk *chunk, *tmp;
	close(s->fd);
	LIST_FOREACH_SAFE(chunk, &s->chunks, next, tmp) free(chunk);
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
	GuppyChunk *chunk = NULL, *last, *tmp;
	char *crlf, *end, *input;
	long eof = 0;
	int len, timeout, i, n, rc, dup;

	if ((len = strlen(url->url)) > (int)sizeof(buffer) - 2) return 4;

	memcpy(buffer, url->url, len);
	buffer[len] = '\r';
	buffer[len + 1] = '\n';

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;

	for (i = 0; i < timeout; ++i) {
request:
		/* send or re-transmit the request */
		if (send(pfd.fd, buffer, len + 2, 0) <= 0) {
			free(chunk);
			if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
			else error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
			return 4;
		}

		pfd.revents = 0;
		if ((n = poll(&pfd, 1, 1000)) == 0) continue;
		if (n < 0) { free(chunk); return 4; }

		while (1) {
			if (chunk == NULL && (chunk = malloc(sizeof(GuppyChunk))) == NULL) { free(chunk); return 4; }

			if ((chunk->length = recv(pfd.fd, chunk->buffer, sizeof(chunk->buffer) - 1, MSG_DONTWAIT)) < 0) {
				/* if we received all incoming packets, resend the request */
				if (errno == EAGAIN || errno == EWOULDBLOCK) goto request;
				error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
				free(chunk);
				return 4;
			}

			if (chunk->length < 5 || (crlf = memchr(chunk->buffer, '\r', chunk->length - 1)) == NULL || *(crlf + 1) != '\n') continue;
			*crlf = '\0';

			if (chunk->buffer[1] == ' ') {
				rc = chunk->buffer[0] - '0';
				if (chunk->buffer[0] == '1') {
					if (!ask) { free(chunk); return 4; }
					if (color) snprintf(prompt, sizeof(prompt), "\33[35m%.*s>\33[0m ", get_terminal_width() - 2, &chunk->buffer[2]);
					else snprintf(prompt, sizeof(prompt), "%.*s> ", get_terminal_width() - 2, &chunk->buffer[2]);
					free(chunk);
					if ((input = bestline(prompt)) == NULL) return 4;
					if (interactive) bestlineHistoryAdd(input);
					if (!set_input(url, input)) { free(input); return 4; }
					free(input);
					if (interactive) bestlineHistoryAdd(url->url);
				} else if (chunk->buffer[0] == '3') {
					if (!redirect(url, &chunk->buffer[2], chunk->length - 4, ask)) { free(chunk); return 4; }
					free(chunk);
				} else if (chunk->buffer[0] == '4') {
					error(0, "cannot download `%s`: %s", url->url, &chunk->buffer[2]);
					free(chunk);
				}
				return rc;
			}

			chunk->seq = strtol(chunk->buffer, &end, 10);
			if (chunk->seq < 6 || chunk->seq > INT_MAX || end == NULL || (*end != ' ' && (*end != '\r' || *(end + 1) != '\n'))) continue;
			*crlf = '\r';
			chunk->skip = crlf - chunk->buffer + 2;

			/* ack the chunk */
			if (!guppy_ack(s->fd, chunk->seq)) { free(chunk); return 4; }

			/* check if we already have this chunk */
			dup = 0;
			LIST_FOREACH_SAFE(last, &s->chunks, next, tmp) {
				dup = dup || (last->seq == chunk->seq);
			}
			if (dup) continue;

			if (!eof && chunk->skip == chunk->length) eof = chunk->seq;

			/* add the chunk to the queue */
			if (last == NULL || *end == ' ') LIST_INSERT_HEAD(&s->chunks, chunk, next);
			else LIST_INSERT_AFTER(last, chunk, next);

			/* if this is not the first chunk, receive another one */
			if (*end != ' ') { chunk = NULL; continue; }

			/* otherwise, free chunks we won't need and stop */
			s->first = chunk->seq;
			*mime = end + 1;
			rc = chunk->seq;

			LIST_FOREACH_SAFE(chunk, &s->chunks, next, tmp) {
				if (chunk->seq < s->first || (eof && chunk->seq > eof)) { LIST_REMOVE(chunk, next); free(chunk); }
			}

			return rc;
		}
	}

	free(chunk);
	error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
	return 4;
}


static void *guppy_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	GuppySocket *s = NULL;
	int status, redirs = 0;

	(void)sel;

	if ((s = malloc(sizeof(GuppySocket))) == NULL) return NULL;
	if ((s->fd = socket_connect(url, SOCK_DGRAM)) == -1) { free(s); return NULL; }
	s->last = -1;
	LIST_INIT(&s->chunks);

	do {
		status = do_guppy_download(url, s, mime, ask);
		/* stop on success, on error or when the redirect limit is exhausted */
		if (status > 5) break;
	} while (((status == 1) || (status == 3)) && ++redirs < 5);

	if (status > 6 && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (status > 6 && strncmp(*mime, "text/plain", 10) == 0) *parser = parse_plaintext_line;
	else if (redirs == 5) error(0, "too many redirects from `%s`", url->url);

	if (status <= 6) { guppy_close(s); return NULL; }
	return s;
}


static int guppy_read(void *c, void *buffer, int length) {
	GuppySocket *s = (GuppySocket*)c;
	GuppyChunk *chunk = NULL, *last, *tmp;
	struct pollfd pfd = {.fd = s->fd, .events = POLLIN};
	char *end;
	int timeout, i, n, ret, dup;

	LIST_FOREACH(chunk, &s->chunks, next) {
		/* if we already have the next chunk, remove it from the queue */
		if ((s->last == -1 && chunk->seq == s->first) || chunk->seq == s->last + 1) {
			LIST_REMOVE(chunk, next);
			goto have;
		}
	}

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;

	for (i = 0; i < timeout; ++i) {
		while (1) {
			if (chunk == NULL && (chunk = malloc(sizeof(GuppyChunk))) == NULL) return -1;

			/* otherwise, receive a chunk */
			if ((chunk->length = recv(s->fd, chunk->buffer, sizeof(chunk->buffer) - 1, MSG_DONTWAIT)) < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) break;
				free(chunk);
				return -1;
			}
			if (chunk->length == 0) { free(chunk); errno = ECONNRESET; return 0; }

			/* extract the sequence number */
			chunk->buffer[chunk->length] = '\0';
			if ((chunk->seq = strtol(chunk->buffer, &end, 10)) < s->first || chunk->seq > INT_MAX || end == NULL || *end != '\r' || *(end + 1) != '\n') continue;
			chunk->skip = end - chunk->buffer + 2;

			/* ack the chunk */
			if (!guppy_ack(s->fd, chunk->seq)) { free(chunk); return -1; }

			/* receive another chunk if we already have this one */
			if (s->last != -1 && chunk->seq <= s->last) continue;
			/* stop if this is the next chunk */
			if (chunk->seq == s->last + 1) goto have;

			/* otherwise, append the chunk to the queue if needed and receive another one */
			dup = 0;
			LIST_FOREACH_SAFE(last, &s->chunks, next, tmp) {
				dup = dup || (last->seq == chunk->seq);
			}
			if (last == NULL) LIST_INSERT_HEAD(&s->chunks, chunk, next);
			else if (dup) continue;
			else LIST_INSERT_AFTER(last, chunk, next);
			chunk = NULL;
		}

		/* wait for the next chunk and resend ack for the previous on timeout */
		if ((n = poll(&pfd, 1, 200)) < 0 || (n == 0 && s->last != -1 && !guppy_ack(s->fd, s->last))) { free(chunk); return -1; }
	}

	free(chunk);
	errno = ETIMEDOUT;
	return -1;

have:
	/* signal EOF if this is the EOF packet */
	if (chunk->skip == chunk->length) { free(chunk); return 0; }

	s->last = chunk->seq;
	ret = (length > chunk->length - chunk->skip ? chunk->length - chunk->skip : length);
	memmove(buffer, chunk->buffer + chunk->skip, ret);
	free(chunk);
	return ret;
}


const Protocol guppy = {"guppy", "6775", guppy_read, NULL, socket_error, guppy_close, guppy_download};
