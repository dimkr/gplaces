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
static void *gophers_download(Selector *sel, char **mime, Parser *parser, int ask) {
	char *buffer;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int len, err;

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) return NULL;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	if ((buffer = gopher_request(sel, ask, &len)) == NULL || (ssl = ssl_connect(sel, ctx, ask)) == NULL) goto fail;
	if ((err = SSL_get_error(ssl, SSL_write(ssl, buffer, len))) != SSL_ERROR_NONE) {
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "cannot send request to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot send request to `%s`:`%s`: error %d", sel->host, sel->port, err);
		SSL_free(ssl); ssl = NULL;
	}

	gopher_type(sel, mime, parser);

fail:
	SSL_CTX_free(ctx);
	return ssl;
}


const Protocol gophers = {"gophers", "70", ssl_read, ssl_error, ssl_close, gophers_download};
