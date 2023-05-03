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
static void parse_spartan_line(char *line, int *pre, Selector **sel, SelectorList *list) {
	if (!*pre && line[0] == '=' && line[1] == ':') {
		line[1] = '>';
		parse_gemtext_line(line, pre, sel, list);
		if (*sel != NULL) (*sel)->prompt = 1;
	} else parse_gemtext_line(line, pre, sel, list);
}


/*============================================================================*/
static int do_spartan_download(URL *url, int *body, char **mime, const char *input, size_t inputlen, int ask) {
	static char buffer[1024], data[1 + 1 + 1024 + 2 + 1]; /* 9 meta\r\n\0 */
	char *crlf, *meta = &data[2];
	int fd = -1, len, total, received, ret = 40;

	len = snprintf(buffer, sizeof(buffer), "%s %s %zu\r\n", url->host, url->path, inputlen);
	if ((fd = tcp_connect(url)) == -1) goto fail;
	if (sendall(fd, buffer, len, MSG_NOSIGNAL) != len || (inputlen > 0 && sendall(fd, input, inputlen, MSG_NOSIGNAL) != (ssize_t)inputlen)) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
		else error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
		goto fail;
	}

	for (total = 0; total < (int)sizeof(data) - 1 && (total < 5 || (data[total - 2] != '\r' && data[total - 1] != '\n')) && (received = recv(fd, &data[total], 1, 0)) > 0; ++total);
	if (total < 5 || data[0] < '2' || data[0] > '5' || (total > 1 && data[1] != ' ') || data[total - 2] != '\r' || data[total - 1] != '\n' || received < 0) goto fail;
	data[total] = '\0';

	crlf = &data[total - 2];
	*crlf = '\0';
	if (meta >= crlf) meta = "";

	switch (data[0]) {
		case '2':
			if (!*meta) goto fail;
			*body = fd;
			fd = -1;
			*mime = meta;
			break;

		case '3':
			if (!*meta) goto fail;
			if (!redirect(url, meta, total - 2, ask)) goto fail;
			fprintf(stderr, "redirected to `%s`\n", url->url);
			break;

		default:
			error(0, "cannot download `%s`: %s", url->url, *meta ? meta : data);
	}

	ret = data[0] - '0';

fail:
	if (fd != -1) close(fd);
	return ret;
}


static void *spartan_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	char *input = NULL, *query = NULL;
	size_t inputlen = 0;
	static int fd = -1;
	int status, redirs = 0;

	switch (curl_url_get(url->cu, CURLUPART_QUERY, &query, 0)) {
	case CURLUE_OK: input = query; break;
	case CURLUE_NO_QUERY: break;
	default: return NULL;
	}
	if (sel->prompt && (input == NULL || *input == '\0')) {
		if (!ask || (input = bestline(color ? "\33[35mData>\33[0m " : "Data> ")) == NULL || !set_input(url, input)) goto fail;
		if (interactive) { bestlineHistoryAdd(input); bestlineHistoryAdd(url->url); }
	}
	if (input != NULL) inputlen = strlen(input);

	do {
		status = do_spartan_download(url, &fd, mime, input, inputlen, ask);
		if (status == 2) break;
	} while (status == 3 && ++redirs < 5);

	if (fd != -1 && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_spartan_line;
	else if (fd != -1 && strncmp(*mime, "text/plain", 10) == 0) *parser = parse_plaintext_line;

	if (redirs == 5) error(0, "too many redirects from `%s`", url->url);

fail:
	if (input != query) free(input);
	curl_free(query);
	return fd == -1 ? NULL : (void *)(intptr_t)fd;
}


const Protocol spartan = {"spartan", "300", tcp_fd, tcp_read, tcp_peek, tcp_error, tcp_close, spartan_download};
