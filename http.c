/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2025  Dima Krasner

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
static void *http_download(const Selector *sel, URL *url, char **mime, Parser *parser, unsigned int redirs, int ask) {
	const char *http_proxy;
	const Protocol *oldproto = url->proto;
	const URL *oldproxy = url->proxy;
	SSL *ssl = NULL;
	URL proxy = {0};

	(void)sel;

	if ((http_proxy = set_var(&variables, "HTTP_PROXY", NULL)) == NULL || *http_proxy == '\0') {
		error(0, "no proxy for `%s`", url->url);
		return NULL;
	}

	if (!parse_url(&proxy, http_proxy, NULL, NULL)) {
		free_url(&proxy);
		error(0, "invalid proxy for `%s`", url->url);
		return NULL;
	}

	fprintf(stderr, "proxying %s through %s\n", url->url, http_proxy);

	url->proxy = &proxy;
	url->proto = &gemini;

	ssl = gemini_download(sel, url, mime, parser, redirs, ask);

	url->proxy = oldproxy;
	url->proto = oldproto;
	free_url(&proxy);

	return ssl;
}


const Protocol http = {"http", "80", ssl_read, ssl_peek, ssl_error, ssl_close, http_download, set_query};
const Protocol https = {"https", "443", ssl_read, ssl_peek, ssl_error, ssl_close, http_download, set_query};
