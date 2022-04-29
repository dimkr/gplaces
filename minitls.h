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

#include <openssl/ssl.h>

#define TLS_WANT_POLLIN (-1) 
#define TLS_WANT_POLLOUT (-2)

#define TLS_PROTOCOL_TLSv1_2 1
#define TLS_PROTOCOL_TLSv1_3 2

struct tls {
	SSL *ssl;
	BIO *bio;
	X509 *cert;
	int err;
};

struct tls_config {};

static inline int tls_config_set_protocols(struct tls_config *config, uint32_t protocols) {
	unsigned int mask = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | ((protocols & TLS_PROTOCOL_TLSv1_2) ? 0 : SSL_OP_NO_TLSv1_2) | ((protocols & TLS_PROTOCOL_TLSv1_3) ? 0 : SSL_OP_NO_TLSv1_3);
	SSL_CTX_set_options((SSL_CTX *)config, mask);
	return 1;
}

static inline struct tls_config *tls_config_new(void) {
	return (struct tls_config *)SSL_CTX_new(TLS_client_method());
}

static inline void tls_config_free(struct tls_config *config) {
	SSL_CTX_free((SSL_CTX *)config);
}

static inline void tls_config_insecure_noverifycert(struct tls_config *config) {
	SSL_CTX_set_verify((SSL_CTX *)config, SSL_VERIFY_NONE, NULL);
}

static inline void tls_config_insecure_noverifyname(struct tls_config *config) {
	(void)config;
}

static inline void tls_config_insecure_noverifytime(struct tls_config *config) {
	(void)config;
}

static inline int tls_config_set_cert_file(struct tls_config *config, const char *cert_file) {
	return SSL_CTX_use_certificate_file((SSL_CTX *)config, cert_file, SSL_FILETYPE_PEM) == 1 ? 0 : -1;
}
    
static inline int tls_config_set_key_file(struct tls_config *config, const char *key_file) {
	return SSL_CTX_use_PrivateKey_file((SSL_CTX *)config, key_file, SSL_FILETYPE_PEM) == 1 ? 0 : -1;
}

static inline struct tls *tls_client(void) {
	return calloc(sizeof(struct tls), 1);
}

static inline int tls_close(struct tls *ctx) {
	(void)ctx;
	return 0;
}

static inline void tls_free(struct tls *ctx) {
	X509_free(ctx->cert);
	if (ctx->ssl) SSL_free(ctx->ssl);
	else if (ctx->bio) BIO_free(ctx->bio);
}

static inline int tls_configure(struct tls *ctx, struct tls_config *config) {
	return ((ctx->ssl = SSL_new((SSL_CTX *)config)) != NULL) ? 0 : -1;
}

static inline int tls_connect_socket(struct tls *ctx, int s, const char *servername) {
	if ((ctx->bio = BIO_new_socket(s, BIO_NOCLOSE)) == NULL || SSL_set_tlsext_host_name(ctx->ssl, servername) == 0) return 0;
	SSL_set_bio(ctx->ssl, ctx->bio, ctx->bio);
	SSL_set_connect_state(ctx->ssl);
	return 1;
}

static inline int tls_handshake(struct tls *ctx) {
	return SSL_do_handshake(ctx->ssl) == 1 ? 0 : -1;
}

static inline const char *tls_peer_cert_hash(struct tls *ctx) {
	static char hex[7 + EVP_MAX_MD_SIZE * 2 + 1] = "SHA256:";
	static unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len, i;

	if (ctx->cert == NULL && (ctx->cert = SSL_get_peer_certificate(ctx->ssl)) == NULL) return NULL;

	if (X509_digest(ctx->cert, EVP_sha256(), md, &len) == 0) return NULL;

	for (i = 0; i < len; ++i) {
		hex[7 + i * 2] = "0123456789ABCDEF"[md[i] >> 4];
		hex[7 + i * 2 + 1] = "0123456789ABCDEF"[md[i] & 0xf];
	}
	hex[len] = '\0';

	return hex;
}

static inline const char *tls_error(struct tls *ctx) {
	static char buf[8];
	snprintf(buf, sizeof(buf), "error %d", ctx->err);
	return buf;
}

static inline ssize_t tls_write(struct tls *ctx, const void *buf, size_t buflen) {
	int ret = SSL_write(ctx->ssl, buf, buflen);
	if (ret > 0) {
		ctx->err = 0;
		return (ssize_t)ret;
	}
	ctx->err = SSL_get_error(ctx->ssl, ret);
	if (ctx->err == SSL_ERROR_WANT_READ) ctx->err = TLS_WANT_POLLIN;
	else if (ctx->err == SSL_ERROR_WANT_WRITE) ctx->err = TLS_WANT_POLLOUT;
	return -1;
}

static inline ssize_t tls_read(struct tls *ctx, void *buf, size_t buflen) {
	int ret = SSL_read(ctx->ssl, buf, buflen);
	if (ret >= 0) {
		ctx->err = 0;
		/* libtls behaves differently, but this is close enough: https://github.com/libressl-portable/openbsd/blob/98a1b8c9937443f672549fb8a012bb4b7b2d5997/src/lib/libtls/tls.c#L749 */
		return (ssize_t)ret;
	}
	ctx->err = SSL_get_error(ctx->ssl, ret);
	if (ctx->err == SSL_ERROR_WANT_READ) ctx->err = TLS_WANT_POLLIN;
	else if (ctx->err == SSL_ERROR_WANT_WRITE) ctx->err = TLS_WANT_POLLOUT;
	return -1;
}