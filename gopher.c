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
static void parse_gophermap_line(char *line, int *pre, Selector **sel, SelectorList *list) {
	char *path, *host, *port;

	(void)pre;

	*sel = NULL;

	if ((line[0] == '.' && line[1] == '\0') || line[0] == '\0') return;

	*sel = new_selector(*line == 'i' ? '`' : 'l');

	if (*(path = line + 1 + strcspn(line + 1, "\t")) == '\0') goto fail;
	*path = '\0';
	++path;
	if (*(host = path + strcspn(path, "\t")) == '\0') goto fail;
	*host = '\0';
	++host;
	if (*(port = host + strcspn(host, "\t")) == '\0') goto fail;
	*port = '\0';
	++port;
	*(port + strcspn(port, "\t")) = '\0';

	(*sel)->repr = str_copy(line + 1);

	if ((*line == '1' || *line == '0' || *line == '7' || *line == '9' || *line == 'g' || *line == 'I' || *line == '8' || *line == '2' || *line == '6' || *line == '5' || *line == '4' || *line == 'T') && (strcmp(port, "70") == 0 ? asprintf(&(*sel)->rawurl, "%s://%s/%c%s", "gopher", host, *line, path) : asprintf(&(*sel)->rawurl, "%s://%s:%s/%c%s", "gopher", host, port, *line, path)) < 0) { (*sel)->rawurl = NULL; goto fail; }
	else if (*line == 'h' && strncmp(path, "URL:", 4) == 0 && !copy_url(*sel, path + 4)) goto fail;

	SIMPLEQ_INSERT_TAIL(list, *sel, next);
	return;

fail:
	free_selector(*sel);
	*sel = NULL;
}


/*============================================================================*/
static char *gopher_request(const Selector *sel, URL *url, int ask, int *len, size_t skip) {
	static char buffer[1024 + 3]; /* path\r\n\0 */
	char *input = NULL, *query = NULL;
	const char *path, *end;

	if (url->path[0] == '/' && url->path[1] == '7') {
		switch (curl_url_get(url->cu, CURLUPART_QUERY, &query, CURLU_URLDECODE)) {
		case CURLUE_OK: input = query; break;
		case CURLUE_NO_QUERY: break;
		default: return NULL;
		}
		if (input == NULL) {
			if (!ask || (input = bestline(color ? "\33[35mQuery>\33[0m " : "Query> ")) == NULL || !set_input(url, input)) return NULL;
			if (interactive) { bestlineHistoryAdd(input); bestlineHistoryAdd(url->url); }
			*len = snprintf(buffer, sizeof(buffer), "%s\t%s\r\n", sel->rawurl + skip + strcspn(sel->rawurl + skip, "/") + 2, input);
		} else {
			path = sel->rawurl + skip + strcspn(sel->rawurl + skip, "/") + 2;
			if ((end = strrchr(path, '?')) == NULL) *len = snprintf(buffer, sizeof(buffer), "%s\t%s\r\n", path, input);
			else *len = snprintf(buffer, sizeof(buffer), "%.*s\t%s\r\n", (int)(end - path), path, input);
		}
		if (input != query) free(input);
		curl_free(query);
	} else if (url->path[0] == '/' && url->path[1] != '\0') *len = snprintf(buffer, sizeof(buffer), "%s\r\n", sel->rawurl + skip + strcspn(sel->rawurl + skip, "/") + 2);
	else *len = snprintf(buffer, sizeof(buffer), "%s\r\n", sel->rawurl + skip + strcspn(sel->rawurl + skip, "/"));

	return buffer;
}


/*============================================================================*/
static void gopher_type(void *c, const URL *url, char **mime, Parser *parser) {
#ifdef GPLACES_USE_LIBMAGIC
	static char buffer[1024];
	magic_t mag;
	ssize_t len, had = 0;
	const char *tmp = NULL;
#else
	static char buffer[2];

	(void)c;
#endif

	if (url->path[1] == '0' || url->path[1] == '+') *parser = parse_plaintext_line;
	else if (url->path[1] == '1' || url->path[1] == '7' || url->path[1] == '\0' || url->path[2] != '/') *parser = parse_gophermap_line;
#ifdef GPLACES_USE_LIBMAGIC
	else {
		if ((len = url->proto->peek(c, buffer, sizeof(buffer))) <= 0 || (mag = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS | MAGIC_ERROR)) == NULL) goto unk;
		if (magic_load(mag, NULL) == -1) { magic_close(mag); goto unk; }
		do {
			if ((tmp = magic_buffer(mag, buffer, (size_t)len)) == NULL) continue;
			if (strncmp(tmp, "text/plain", 10) == 0) *parser = parse_plaintext_line;
			strncpy(buffer, tmp, sizeof(buffer));
			buffer[sizeof(buffer) - 1] = '\0';
			*mime = buffer;
			had = len;
		} while (len < (ssize_t)sizeof(buffer) && (len = url->proto->peek(c, buffer, sizeof(buffer))) > 0 && len > had);
		magic_close(mag);
		if (tmp != NULL) return;
	}
unk:
#endif

	buffer[0] = (url->path[1] != '\0' && url->path[1] != '/' && url->path[2] == '/') ? url->path[1] : '1';
	buffer[1] = '\0';
	*mime = buffer;
}


static void *gopher_download(const Selector *sel, URL *url, char **mime, Parser *parser, int ask) {
	char *buffer;
	int fd = -1, len;

	if ((buffer = gopher_request(sel, url, ask, &len, 9)) == NULL || (fd = socket_connect(url, SOCK_STREAM)) == -1) goto fail;
	if (sendall(fd, buffer, len, MSG_NOSIGNAL) != len) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", url->host, url->port);
		else error(0, "cannot send request to `%s`:`%s`: %s", url->host, url->port, strerror(errno));
		close(fd); fd = -1;
	}

	if (fd != -1) gopher_type((void *)(intptr_t)fd, url, mime, parser);

fail:
	return fd == -1 ? NULL : (void *)(intptr_t)fd;
}


const Protocol gopher = {"gopher", "70", socket_read, socket_peek, socket_error, socket_close, gopher_download};
