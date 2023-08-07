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


static int guppy_ack(int fd, long seq, int more) {
	static char buffer[1024];
	char ack[12];
	int length;
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	long nextseq;
	char *end;
	int i, n, timeout;
	ssize_t pending;
	length = sprintf(ack, "%ld\r\n", seq);
	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;
	for (i = 0; i < timeout; ++i) {
		if (send(fd, ack, length, MSG_NOSIGNAL) != (ssize_t)length) return 0;
		if (!more) return 1;
		while (1) {
			if ((pending = recv(fd, buffer, sizeof(buffer) - 1, MSG_PEEK | MSG_NOSIGNAL | MSG_DONTWAIT)) == 0) return -1;
			if (pending == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
			buffer[pending] = '\0';
			if ((nextseq = strtol(buffer, &end, 10)) == LONG_MIN || seq == LONG_MAX || end == NULL || (*end != ' ' && *end != '\r')) continue;
			if (nextseq == seq + 1) return 1;
			if (recv(fd, buffer, sizeof(buffer) - 1, MSG_NOSIGNAL | MSG_DONTWAIT) <= 0) return -1;
		}
		pfd.revents = 0;
		if ((n = poll(&pfd, 1, 1000)) < 0 || (n > 0 && !(pfd.revents & POLLIN))) return -1;
	}
	return 0;
}


static int do_guppy_download(URL *url, int *body, char **mime, const char *input, size_t inputlen, int ask) {
	static char buffer[1024];
	char *crlf, *space, *meta;
	int fd = -1, len, received, ret = 1;

	if ((len = strlen(url->url)) + 2 + inputlen > sizeof(buffer)) goto fail;

	if ((fd = socket_connect(url, SOCK_DGRAM)) == -1) goto fail;

	memcpy(buffer, url->url, len);
	buffer[len] = '\r';
	buffer[len + 1] = '\n';
	memcpy(&buffer[len + 2], input, inputlen);

	if (send(fd, buffer, len + 2 + inputlen, MSG_NOSIGNAL) != (ssize_t)(len + 2 + inputlen) || (received = recv(fd, buffer, sizeof(buffer), MSG_PEEK | MSG_NOSIGNAL)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
		else error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
		goto fail;
	}
	if (received < 5 || (space = memchr(buffer, ' ', received - 2)) == NULL || (crlf = memchr(space, '\r', received - (space - buffer) - 1)) == NULL || crlf <= (space + 1) || *(crlf + 1) != '\n') goto fail;
	*crlf = '\0';
	meta = space + 1;

	if (buffer[0] == '0' && buffer[1] == ' ') {
		if (!redirect(url, meta, received - 4, ask)) goto fail;
	} else if (buffer[0] == '1' && buffer[1] == ' ') {
		error(0, "cannot download `%s`: %s", url->url, meta);
	} else {
		*body = fd;
		fd = -1;
		*mime = meta;
	}

	ret = buffer[0] - '0';

fail:
	if (fd != -1) close(fd);
	return ret;
}


static void *guppy_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	char *input = NULL, *query = NULL;
	size_t inputlen = 0;
	static int fd = -1;
	int status, redirs = 0;

	(void)sel;

	switch (curl_url_get(url->cu, CURLUPART_QUERY, &query, 0)) {
	case CURLUE_OK: input = query; break;
	case CURLUE_NO_QUERY: break;
	default: return NULL;
	}

	do {
		status = do_guppy_download(url, &fd, mime, input, inputlen, ask);
		if (status > 1) break;
	} while (status == 0 && ++redirs < 5);

	if (fd != -1 && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (fd != -1 && strncmp(*mime, "text/plain", 10) == 0) *parser = parse_plaintext_line;

	if (redirs == 5) error(0, "too many redirects from `%s`", url->url);

	curl_free(query);
	return fd == -1 ? NULL : (void *)(intptr_t)fd;
}


static int guppy_read(void *c, void *buffer, int length) {
	int received, skip;
	char *crlf, *end;
	long seq;
	if ((received = (int)recv((int)(intptr_t)c, buffer, (size_t)length, 0)) <= 0 || (crlf = memchr(buffer, '\r', received - 1)) == NULL || crlf == buffer || *(crlf + 1) != '\n') return received;
	*crlf = '\0';
	if ((seq = strtol((char *)buffer, &end, 10)) == LONG_MIN || seq == LONG_MAX || end == NULL || (*end != ' ' && *end != '\0')) return -1;
	if (!guppy_ack((int)(intptr_t)c, seq, received > skip)) return -1;
	if ((skip = crlf - (char *)buffer + 2) == received) return 0;
	memmove(buffer, crlf + 2, received - skip);
	return received - skip;
}


const Protocol guppy = {"guppy", "6775", guppy_read, NULL, socket_error, socket_close, guppy_download};
