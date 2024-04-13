/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2024  Dima Krasner

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
typedef struct TitanParams {
	char *url;
	char *token;
	const char *mime;
	struct stat stbuf;
	void *body;
} TitanParams;


/*============================================================================*/
static int titan_request(const URL *url, SSL *ssl, void *p) {
	static char buffer[1024];
	const TitanParams *params = (const TitanParams *)p;
	int len, err;

	(void)url;

	len = snprintf(buffer, sizeof(buffer), params->token == NULL || *params->token == '\0' ? "%s;mime=%s;size=%zu\r\n" : "%s;mime=%s;size=%zu;token=%s\r\n", params->url, params->mime, params->stbuf.st_size, params->token);
	if ((err = SSL_get_error(ssl, SSL_write(ssl, buffer, len >= (int)sizeof(buffer) ? (int)sizeof(buffer) - 1 : len))) != SSL_ERROR_NONE) return err;

	return params->stbuf.st_size > 0 ? SSL_get_error(ssl, SSL_write(ssl, params->body, params->stbuf.st_size)) : SSL_ERROR_NONE;
}


static void *titan_upload(const Selector *sel, URL *url, char **mime, Parser *parser, unsigned int redirs, int ask) {
#ifdef GPLACES_USE_LIBMAGIC
	magic_t mag = NULL;
#else
	char *tmp;
#define magic_close(x) do {} while (0)
#endif
	CURLU *cu;
	TitanParams params = {.mime = "application/octet-stream"};
	char *fragment, *path = NULL;
	SSL *ssl = NULL;
	int fd, status = -1;

	(void)sel;

	if ((cu = curl_url_dup(url->cu)) == NULL || curl_url_set(cu, CURLUPART_FRAGMENT, NULL, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK || curl_url_get(cu, CURLUPART_URL, &params.url, 0) != CURLUE_OK) { curl_url_cleanup(cu); return NULL; }
	curl_url_cleanup(cu);

	switch (curl_url_get(url->cu, CURLUPART_FRAGMENT, &fragment, 0)) {
	case CURLUE_OK: path = fragment; break;
	case CURLUE_NO_FRAGMENT: break;
	default: return NULL;
	}

	if (path == NULL || *path == '\0') {
		if (!ask || (params.token = bestline("Token> ")) == NULL) { curl_free(params.url); return NULL; }
		if (interactive) bestlineHistoryAdd(params.token);
		if ((path = bestline("File> ")) == NULL) { free(params.token); curl_free(params.url); return NULL; }
		if (interactive) bestlineHistoryAdd(path);
	}

	if ((fd = open(path, O_RDONLY)) == -1) { error(0, "cannot open `%s`: %s", path, strerror(errno)); free(path); free(params.token); curl_free(params.url); return NULL; }
	if (fstat(fd, &params.stbuf) == -1) { error(0, "cannot open `%s`: %s", path, strerror(errno)); close(fd); free(path); free(params.token); curl_free(params.url); return NULL; }
	if (params.stbuf.st_size > 0 && (params.body = mmap(NULL, params.stbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) { error(0, "cannot open `%s`: %s", path, strerror(errno)); close(fd); free(path); free(params.token); curl_free(params.url); return NULL; }

	if (params.stbuf.st_size > 0) {
#ifdef GPLACES_USE_LIBMAGIC
		if ((mag = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS | MAGIC_ERROR)) == NULL) { munmap(params.body, params.stbuf.st_size); close(fd); free(path); free(params.token); curl_free(params.url); return NULL; }
		if (magic_load(mag, NULL) != 0) { munmap(params.body, params.stbuf.st_size); close(fd); free(path); free(params.token); magic_close(mag); curl_free(params.url); return NULL; }
		if ((params.mime = magic_buffer(mag, params.body, params.stbuf.st_size)) == NULL) { error(0, "cannot open `%s`: %s", path, magic_error(mag)); munmap(params.body, params.stbuf.st_size); close(fd); free(path); free(params.token); magic_close(mag); curl_free(params.url); return NULL; }
#else
		if ((tmp = bestline("File type> ")) == NULL) { munmap(params.body, params.stbuf.st_size); close(fd); free(path); free(params.token); curl_free(params.url); return NULL; }
		if (interactive) bestlineHistoryAdd(tmp);
		params.mime = tmp;
#endif
	}

	do {
		status = ssl_download(url, &ssl, mime, titan_request, &params, ask);
		if (status >= 20 && status <= 29) break;
	} while ((status >= 10 && status <= 19) || (status >= 60 && status <= 69) || (status >= 30 && status <= 39 && ++redirs < 5 && url->proto->download == titan_upload));

	if (params.stbuf.st_size > 0) munmap(params.body, params.stbuf.st_size);
	close(fd);
	free(params.token);
	if (path != fragment) free(path);
#ifdef GPLACES_USE_LIBMAGIC
	if (mag != NULL) magic_close(mag);
#else
	free(tmp);
#endif
	curl_free(fragment);
	curl_free(params.url);

	if (redirs < 5 && url->proto->download != titan_upload) return url->proto->download(sel, url, mime, parser, redirs, ask);

	if (ssl != NULL && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (ssl != NULL && (!interactive || strncmp(*mime, "text/plain", 10) == 0)) *parser = parse_plaintext_line;

	if (redirs == 5) error(0, "too many redirects from `%s`", url->url);
	return ssl;
}


const Protocol titan = {"titan", "1965", ssl_read, ssl_peek, ssl_error, ssl_close, titan_upload, set_fragment};
