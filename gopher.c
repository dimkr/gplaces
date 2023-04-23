/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2022  Dima Krasner

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
	(*sel)-> prompt = *line == '7';

	path = line + 1 + strcspn(line + 1, "\t");
	*path = '\0';
	++path;
	host = path + strcspn(path, "\t");
	*host = '\0';
	++host;
	if ((port = host + strcspn(host, "\t")) == host) goto fail;
	*port = '\0';
	++port;
	*(port + strcspn(port, "\t")) = '\0';

	(*sel)->repr = str_copy(line + 1);

	if ((*line == '1' || *line == '0' || *line == '7' || *line == '9' || *line == 'g' || *line == 'I' || *line == '8' || *line == '2' || *line == '6' || *line == '5' || *line == '4' || *line == 'T') && asprintf(&(*sel)->rawurl, "%s://%s:%s/%c%s", gopher.scheme, host, port, *line, path) < 0) { (*sel)->rawurl = NULL; goto fail; }
	else if (*line == 'h' && strncmp(path, "URL:", 4) == 0 && !copy_url(*sel, path + 4)) goto fail;

	SIMPLEQ_INSERT_TAIL(list, *sel, next);
	return;

fail:
	free_selector(*sel);
	*sel = NULL;
}


/*============================================================================*/
static char *gopher_request(Selector *sel, int ask, int *len) {
	static char buffer[1024 + 3]; /* path\r\n\0 */
	char *query = NULL, *criteria = NULL;

	if (sel->prompt || strncmp(sel->path, "/7/", 3) == 0) {
		switch (curl_url_get(sel->cu, CURLUPART_QUERY, &query, 0)) {
		case CURLUE_OK: criteria = query; break;
		case CURLUE_NO_QUERY: break;
		default: return NULL;
		}
		if (criteria == NULL || *criteria == '\0')  {
			if (!ask || (criteria = bestline(color ? "\33[35mSearch criteria>\33[0m " : "Search criteria> ")) == NULL) { curl_free(query); return NULL; }
			if (interactive) bestlineHistoryAdd(criteria);
		}
	}
	if (criteria && *criteria != '\0') *len = snprintf(buffer, sizeof(buffer), "%s\t%s\r\n", strncmp(sel->path, "/7/", 3) == 0 ? sel->path + 2 : sel->path, criteria);
	else *len = snprintf(buffer, sizeof(buffer), "%s\r\n", (sel->path[0] != '\0' && sel->path[1] != '/' && sel->path[1] != '\0' && sel->path[2] == '/') ? sel->path + 2 : sel->path);

	if (criteria != query) free(criteria);
	curl_free(query);
	return buffer;
}


/*============================================================================*/
static void gopher_type(Selector *sel, char **mime, Parser *parser) {
	static char buffer[2];

	buffer[0] = (sel->path[1] != '\0' && sel->path[1] != '/' && sel->path[2] == '/') ? sel->path[1] : '1';
	buffer[1] = '\0';
	*mime = buffer;

	if (sel->path[1] == '0' || sel->path[1] == '+') *parser = parse_plaintext_line;
	else if (sel->path[1] == '1' || sel->path[1] == '7' || sel->path[1] == '\0' || sel->path[2] != '/') *parser = parse_gophermap_line;
}


static void *gopher_download(Selector *sel, char **mime, Parser *parser, int ask) {
	char *buffer;
	int fd = -1, len;

	if ((buffer = gopher_request(sel, ask, &len)) == NULL || (fd = tcp_connect(sel)) == -1) goto fail;
	if (sendall(fd, buffer, len, MSG_NOSIGNAL) != len) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "cannot send request to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot send request to `%s`:`%s`: %s", sel->host, sel->port, strerror(errno));
		close(fd); fd = -1;
	}

	gopher_type(sel, mime, parser);

fail:
	return fd == -1 ? NULL : (void *)(intptr_t)fd;
}


const Protocol gopher = {"gopher", "70", tcp_read, tcp_error, tcp_close, gopher_download};
