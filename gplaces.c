/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2022  Dima Krasner
    Copyright (C) 2019  Sebastian Steinhauer

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
/*============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <regex.h>
#include "queue.h"

#ifdef GPLACES_USE_MBEDTLS
	#include <mbedtls/net_sockets.h>
	#include <mbedtls/entropy.h>
	#include <mbedtls/ctr_drbg.h>
	#include <mbedtls/ssl.h>
	#include <mbedtls/x509.h>
	#include <mbedtls/base64.h>
	#include <mbedtls/error.h>
#else
	#include <openssl/ssl.h>
	#include <openssl/bio.h>
	#include <openssl/sha.h>
	#include <openssl/err.h>
#endif

#include <curl/curl.h>

#ifdef GPLACES_USE_LIBMAGIC
	#include <magic.h>
#endif

#include "bestline/bestline.h"

/*============================================================================*/
typedef struct Selector {
	SIMPLEQ_ENTRY(Selector) next;
	int index;
	char type, *raw, *repr, *scheme, *host, *port, *path, *url;
	CURLU *cu;
} Selector;

typedef SIMPLEQ_HEAD(, Selector) SelectorList;

typedef struct Variable {
	LIST_ENTRY(Variable) next;
	char *name, *data;
} Variable;

typedef LIST_HEAD(, Variable) VariableList;

typedef struct Command {
	const char *name;
	void (*func)(char *line);
} Command;

typedef struct Help {
	const char *name;
	const char *text;
} Help;


/*============================================================================*/
static VariableList variables = LIST_HEAD_INITIALIZER(variables);
static VariableList aliases = LIST_HEAD_INITIALIZER(aliases);
static VariableList typehandlers = LIST_HEAD_INITIALIZER(typehandlers);
static SelectorList bookmarks = SIMPLEQ_HEAD_INITIALIZER(bookmarks);
static SelectorList subscriptions = SIMPLEQ_HEAD_INITIALIZER(subscriptions);
static SelectorList menu = SIMPLEQ_HEAD_INITIALIZER(menu);
static char prompt[256] = "(\33[35m\33[0m)> ";
static int interactive;


/*============================================================================*/
static void vlogf(FILE *fp, const char *color, const char *fmt, va_list va) {
	if (interactive) fprintf(fp, "\33[%sm", color);
	vfprintf(fp, fmt, va);
	if (interactive) fputs("\33[0m\n", fp);
	else fputc('\n', fp);
}

static void error(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	vlogf(stderr, "31", fmt, va);
	va_end(va);
}

static void panic(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	vlogf(stderr, "31", fmt, va);
	va_end(va);
	exit(EXIT_FAILURE);
}


/*============================================================================*/
static char *str_copy(const char *str) {
	char *new;
	if ((new = strdup(str)) == NULL) panic("cannot allocate new string");
	return new;
}

static char *str_skip(char *str, const char *delim) {
	while (*str && strchr(delim, *str)) ++str;
	return str;
}

static char *str_split(char **str, const char *delim) {
	char *begin;
	if (*str == NULL || **str == '\0') return NULL;
	for (begin = *str; *str && !strchr(delim, **str); ++*str) ;
	if (**str != '\0') { **str = '\0'; ++*str; }
	return begin;
}

static char *str_next(char **str, const char *delims) {
	char *begin;
	if (*str == NULL || **str == '\0') return NULL;
	begin = *str + strspn(*str, delims);
	*str = begin + strcspn(begin, delims);
	if (**str != '\0') { **str = '\0'; ++*str; }
	return begin;
}


/*============================================================================*/
static void free_variables(VariableList *vars) {
	Variable *var, *tmp;
	LIST_FOREACH_SAFE(var, vars, next, tmp) {
		free(var->name);
		free(var->data);
		free(var);
	}
}


static char *set_var(VariableList *list, const char *name, const char *fmt, ...) {
	Variable *var;

	if (name == NULL) return NULL;
	LIST_FOREACH(var, list, next) {
		if (!strcasecmp(var->name, name)) break;
	}

	if (fmt) {
		va_list va;
		static char buffer[1024];

		va_start(va, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, va);
		va_end(va);

		if (var == NULL) {
			if ((var = malloc(sizeof(Variable))) == NULL) panic("cannot allocate new variable");
			var->name = str_copy((char*)name);
			var->data = str_copy(buffer);
			LIST_INSERT_HEAD(list, var, next);
		} else {
			free(var->data);
			var->data = str_copy(buffer);
		}
	}

	return var ? var->data : NULL;
}


static int get_var_integer(const char *name, int def) {
	int value;
	char *data = set_var(&variables, name, NULL);
	if (data == NULL || sscanf(data, "%d", &value) != 1) return def;
	return value;
}


/*============================================================================*/
static Selector *new_selector(const char type, const char *raw) {
	Selector *new = calloc(1, sizeof(Selector));
	if (new == NULL) panic("cannot allocate new selector");
	new->type = type;
	new->raw = str_copy(raw);
	return new;
}


static void free_selector(Selector *sel) {
	free(sel->raw);
	free(sel->repr);
	curl_free(sel->scheme);
	curl_free(sel->host);
	curl_free(sel->port);
	curl_free(sel->path);
	curl_free(sel->url);
	if (sel->cu) curl_url_cleanup(sel->cu);
	free(sel);
}


static void free_selectors(SelectorList *list) {
	Selector *sel, *tmp;
	SIMPLEQ_FOREACH_SAFE(sel, list, next, tmp) free_selector(sel);
}


static int set_selector_url(Selector *sel, Selector *from, const char *url) {
	static char buffer[1024];

	/* TODO: why does curl_url_set() return CURLE_OUT_OF_MEMORY if the scheme is missing, but only inside the Flatpak sandbox? */
	if (curl_url_set(sel->cu, CURLUPART_URL, url, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) {
		if (from) return 0;
		snprintf(buffer, sizeof(buffer), "gemini://%s", url);
		if (curl_url_set(sel->cu, CURLUPART_URL, buffer, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) return 0;
	}

	if (curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_SCHEME, &sel->scheme, 0) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_PATH, &sel->path, 0) != CURLUE_OK) return 0;

	if (!strcmp(sel->scheme, "file")) {
		sel->host = str_copy("");
		sel->port = str_copy("");
		return 1;
	}

	if (curl_url_get(sel->cu, CURLUPART_HOST, &sel->host, 0) != CURLUE_OK) return 0;

	switch (curl_url_get(sel->cu, CURLUPART_PORT, &sel->port, 0)) {
		case CURLUE_OK: break;
		case CURLUE_NO_PORT: sel->port = str_copy("1965"); break;
		default: free_selector(sel); return 0;
	}

	return 1;
}


static Selector *find_selector(SelectorList *list, const char *line) {
	Selector *sel;
	int index;
	if ((index = atoi(line)) <= 0) return NULL;
	SIMPLEQ_FOREACH(sel, list, next) if (sel->index == index) return sel;
	return NULL;
}


static int parse_url(Selector *from, Selector *sel, const char *url) {
	if (url == NULL || *url == '\0') return 0;

	sel->cu = (from && from->cu) ? curl_url_dup(from->cu) : curl_url();
	if (!sel->cu || !set_selector_url(sel, from, url)) return 0;

	return 1;
}


static SelectorList parse_gemtext(Selector *from, FILE *fp) {
	static char buffer[1024];
	char *line, *url;
	SelectorList list = SIMPLEQ_HEAD_INITIALIZER(list);
	Selector *sel;
	size_t len;
	int pre = 0, i, index = 1;

	for (i = 0; i < 512 && (line = fgets(buffer, sizeof(buffer), fp)) != NULL; ++i) {
		if (strncmp(line, "```", 3) == 0) {
			pre = !pre;
			continue;
		}

		len = strlen(line);
		if (len >= 2 && line[len - 2] == '\r') line[len - 2] = '\0';
		else if (line[len - 1] == '\n') line[len - 1] = '\0';

		if (pre) {
			sel = new_selector('`', line);
			sel->repr = str_copy(line);
		} else if (line[0] == '=' && line[1] == '>') {
			sel = new_selector('l', line);
			line += 2;
			url = str_next(&line, " \t\r\n");
			if (!parse_url(from, sel, url)) { free_selector(sel); continue; }
			if (*line) {
				free(sel->repr);
				sel->repr = str_copy(*line ? line : url);
			} else sel->repr = str_copy(url);
			sel->index = index++;
		} else if (*line == '#') {
			sel = new_selector('#', line);
			sel->repr = str_copy(line);
		} else if (*line == '>') {
			sel = new_selector('>', line);
			str_next(&line, " \t\r\n");
			sel->repr = str_copy(line);
		} else if (line[0] == '*' && line[1] == ' ') {
			sel = new_selector('*', line);
			str_next(&line, " \t\r\n");
			sel->repr = str_copy(line);
		} else {
			sel = new_selector('i', line);
			sel->repr = str_copy(line);
		}

		SIMPLEQ_INSERT_TAIL(&list, sel, next);
	}

	if (i == 512) error("gemtext is truncated to 512 lines");

	return list;
}


/*============================================================================*/
static char *next_token(char **str) {
	if (*str == NULL) return NULL;
	*str = str_skip(*str, " \v\t");
	switch (**str) {
		case '\0': case '#': return NULL;
		case '"': ++*str; return str_split(str, "\"");
		case '$': {
			char *data;
			++*str;
			data = set_var(&variables, str_split(str, " \v\t"), NULL);
			return data ? data : "";
		}
		default: return str_split(str, " \v\t");
	}
}


static char *read_line(const char *fmt, ...) {
	static char buffer[256];
	char *line;
	if (fmt != NULL) {
		va_list va;
		va_start(va, fmt);
		vprintf(fmt, va);
		va_end(va);
		fflush(stdout);
	}
	memset(buffer, 0, sizeof(buffer));
	if ((line = fgets(buffer, sizeof(buffer), stdin)) == NULL) return NULL;
	line = str_skip(line, " \v\t");
	line = str_split(&line, "\r\n");
	return line ? line : "";
}


static int get_terminal_height() {
	struct winsize wz;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &wz);
	return wz.ws_row - 2; /* substract 2 lines (1 for tmux etc., 1 for the prompt) */
}


static int get_terminal_width() {
	struct winsize wz;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &wz);
	return wz.ws_col > 80 ? wz.ws_col : 80;
}


/*============================================================================*/
static const char *find_mime_handler(const char *mime) {
	const char *handler = set_var(&typehandlers, mime, NULL);
	if (!handler)
		fprintf(stderr, "no handler for `%s`\n", mime);
	return handler;
}


static void reap(const char *command, pid_t pid) {
	pid_t ret;
	int status;

	for (;;) {
		ret = waitpid(pid, &status, 0);
		if (ret < 0 && errno == EINTR) continue;
		if (ret == pid && WIFEXITED(status)) fprintf(stderr, "`%s` has exited with exit status %d\n", command, WEXITSTATUS(status));
		else if (ret == pid && !WIFEXITED(status)) fprintf(stderr, "`%s` has exited abnormally\n", command);
		break;
	}
}


static void execute_handler(const char *handler, const char *filename, Selector *to) {
	static char command[1024];
	size_t l;
	pid_t pid;
	int fd;

	for (l = 0; *handler && l < sizeof(command) - 1; ) {
		if (handler[0] == '%' && handler[1] != '\0') {
			const char *append = "";
			switch (handler[1]) {
				case '%': append = "%"; break;
				case 's': append = to->scheme; break;
				case 'h': append = to->host; break;
				case 'p': append = to->port; break;
				case 'P': append = to->path; break;
				case 'r': append = to->repr; break;
				case 'u': append = to->url; break;
				case 'f': append = filename; break;
			}
			handler += 2;
			while (*append && l < sizeof(command) - 1) command[l++] = *append++;
		} else command[l++] = *handler++;
	}
	command[l] = '\0';

	if ((pid = fork()) == 0) {
		if ((fd = open("/dev/null", O_RDWR)) != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
			execl("/bin/sh", "sh", "-c", command, (char *)NULL);
		}
		exit(EXIT_FAILURE);
	} else if (pid > 0) reap(command, pid);
	else error("could not execute `%s`", command);
}


/*============================================================================*/
#ifdef GPLACES_USE_MBEDTLS
static int tofu(const mbedtls_x509_crt *cert) {
#else
static int tofu(X509 *cert) {
#endif
	static char hosts[1024], buffer[2048], namebuf[1024];
	const char *home;
	char *line;
	size_t hlen;
	FILE *fp;
	int trust = 1, namelen;

#ifndef GPLACES_USE_MBEDTLS
	X509_NAME *name;
	EVP_PKEY *pub;
	BIGNUM *bn;
	char *hex, *p;
	size_t len;

	if ((name = X509_get_subject_name(cert)) == NULL) return 0;
	if ((namelen = X509_NAME_get_text_by_NID(name, NID_commonName, namebuf, sizeof(namebuf))) <= 0) return 0;

	if ((fp = open_memstream(&p, &len)) == NULL) return 0;
	if ((pub = X509_get_pubkey(cert)) == NULL) return 0;
	i2d_PUBKEY_fp(fp, pub);
	fclose(fp);
	bn = BN_bin2bn((const unsigned char *)p, len, NULL);
	free(p);
	if (!bn) return 0;

	hex = BN_bn2hex(bn);
	BN_free(bn);
	if (!hex) return 0;
	hlen = strlen(hex);
#else
	char hex[2048];

	if ((namelen = mbedtls_x509_dn_gets(namebuf, sizeof(namebuf), &cert->subject)) < 4) return 0;
	if (mbedtls_base64_encode((unsigned char *)hex, sizeof(hex), &hlen, (unsigned char *)namebuf, namelen) != 0) return 0;
#endif

	if ((home = getenv("HOME")) == NULL) return 0;
	snprintf(hosts, sizeof(hosts), "%s/.gplaces_hosts", home);
	if ((fp = fopen(hosts, "r")) != NULL) {
		while ((line = fgets(buffer, sizeof(buffer), fp)) != NULL) {
			if (strncmp(line, namebuf, namelen)) continue;
			if (line[namelen] != ' ') continue;
			trust = strncmp(&line[namelen + 1], hex, hlen) == 0 && line[namelen + 1 + hlen] == '\n';
			goto out;
		}

		fclose(fp); fp = NULL;
	}

	if (trust) trust = (fp = fopen(hosts, "a")) != NULL && fprintf(fp, "%s %s\n", namebuf, hex) > 0;

out:
	if (fp) fclose(fp);
#ifndef GPLACES_USE_MBEDTLS
	OPENSSL_free(hex);
#endif
	return trust;
}


static int write_all(FILE *fp, const char *buffer, size_t length) {
	size_t total = 0, out;

	do {
		if ((out = fwrite(&buffer[total], 1, length - total, fp)) == 0) return 0;
		total += out;
	} while (total < length);

	return 1;
}


#ifdef GPLACES_USE_MBEDTLS
static int do_download(Selector *sel, mbedtls_ssl_config *conf, FILE *fp, char **mime, int ask) {
#else
static int do_download(Selector *sel, SSL_CTX *ctx, FILE *fp, char **mime, int ask) {
#endif
	struct addrinfo hints, *result, *it;
	static char request[1024];
	char *data = NULL, *crlf, *meta, *line;
	struct timeval tv = {0};
	size_t total, chunks = 0, cap = 2 + 1 + 1024 + 2 + 2048 + 1; /* 99 meta\r\n\body0 */
	int timeout, fd = -1, received, ret = 40;
#ifdef GPLACES_USE_MBEDTLS
	static char errbuf[512];
	mbedtls_ssl_context ssl;
	const mbedtls_x509_crt *cert;
	mbedtls_net_context net = {0};
	int err;

	mbedtls_ssl_init(&ssl);
#else
	BIO *bio = NULL;
	SSL *ssl = NULL;
	X509 *cert = NULL;
#endif

	timeout = get_var_integer("TIMEOUT", 15);
	if (timeout <= 1) timeout = 15;
	tv.tv_sec = timeout;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(sel->host, sel->port, &hints, &result) || result == NULL) {
		error("cannot resolve hostname `%s`", sel->host);
		goto fail;
	}

	for (it = result; it; it = it->ai_next) {
		if ((fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol)) == -1) continue;
		if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
		close(fd); fd = -1;
	}

	freeaddrinfo(result);

	if (fd == -1) {
		error("cannot connect to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#ifdef GPLACES_USE_MBEDTLS
	if (mbedtls_ssl_setup(&ssl, conf) != 0) goto fail;

	net.fd = fd;
	mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
	if (mbedtls_ssl_set_hostname(&ssl, sel->host) != 0) goto fail;

	if ((err = mbedtls_ssl_handshake(&ssl)) != 0) {
		mbedtls_strerror(err, errbuf, sizeof(errbuf));
		error("cannot establish secure connection to `%s`:`%s`: %s", sel->host, sel->port, errbuf);
		goto fail;
	}
	if ((cert = mbedtls_ssl_get_peer_cert(&ssl)) == NULL) {
		error("cannot establish secure connection to `%s`:`%s`: no certificate", sel->host, sel->port);
		goto fail;
	}
#else
	if ((ssl = SSL_new(ctx)) == NULL || (bio = BIO_new_socket(fd, BIO_NOCLOSE)) == NULL) {
		error("cannot establish secure connection to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}
 
	SSL_set_tlsext_host_name(ssl, sel->host);
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);

	if (SSL_do_handshake(ssl) != 1 || (cert = SSL_get_peer_certificate(ssl)) == NULL) {
		error("cannot establish secure connection to `%s`:`%s`: %s", sel->host, sel->port, ERR_reason_error_string(ERR_get_error()));
		goto fail;
	}
#endif

	if (!tofu(cert)) {
		error("cannot establish secure connection to `%s`:`%s`: certificate has changed", sel->host, sel->port);
		goto fail;
	}

	snprintf(request, sizeof(request), "%s\r\n", sel->url);
#ifdef GPLACES_USE_MBEDTLS
	if (mbedtls_ssl_write(&ssl, (unsigned char *)request, strlen(request)) == 0) {
#else
	if (SSL_write(ssl, request, strlen(request)) == 0) {
#endif
		error("cannot send request to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}

	if ((data = malloc(cap)) == NULL) panic("cannot allocate download data");

	for (total = 0; total < cap - 1 && (total < 4 || (data[total - 2] != '\r' && data[total - 1] != '\n')); ++total) {
#ifdef GPLACES_USE_MBEDTLS
		if ((received = mbedtls_ssl_read(&ssl, (unsigned char *)&data[total], 1)) > 0) continue;
		if (received == 0 || received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
		mbedtls_strerror(received, errbuf, sizeof(errbuf));
		error("failed to download `%s`: %s", sel->url, errbuf);
#else
		if ((received = SSL_read(ssl, &data[total], 1)) > 0) continue;
		if (received == 0 || SSL_get_error(ssl, received) == SSL_ERROR_ZERO_RETURN) break;
		error("failed to download `%s`: %s", sel->url, ERR_reason_error_string(ERR_get_error()));
#endif
		goto fail;
	}
	if (data[1] < '0' || data[0] > '9' || data[1] < '0' || data[1] > '9' || data[total - 2] != '\r' || data[total - 1] != '\n') goto fail;
	data[total] = '\0';

	crlf = &data[total - 2];
	*crlf = '\0';
	meta = &data[3];
	if (data[2] != ' ' || meta >= crlf) meta = "";

	switch (data[0]) {
		case '2':
			if (!*meta) goto fail;
			break;

		case '1':
			if (!ask || !*meta) goto fail;
			snprintf(prompt, sizeof(prompt), "(\33[35m%s\33[0m)> ", meta);
			if ((line = bestline(prompt)) == NULL) goto fail;
			bestlineHistoryAdd(line);
			if (curl_url_set(sel->cu, CURLUPART_QUERY, line, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK) { free(line); goto fail; }
			free(line);
			break;

		case '3':
			if (!*meta) goto fail;
			if (curl_url_set(sel->cu, CURLUPART_URL, meta, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK) goto fail;
			break;

		default:
			error("failed to download `%s`: %s", sel->url, *meta ? meta : data);
	}

	for (;;) {
#ifdef GPLACES_USE_MBEDTLS
		if ((received = mbedtls_ssl_read(&ssl, (unsigned char *)crlf + 1, cap - (crlf - data) - 1)) > 0) {
#else
		if ((received = SSL_read(ssl, crlf + 1, cap - (crlf - data) - 1)) > 0) {
#endif
			if (!write_all(fp, crlf + 1, received)) goto fail;
			total += received;
			if (total > 2048 && interactive && ++chunks <= 80) fputc('.', stderr);
			continue;
		}
#ifdef GPLACES_USE_MBEDTLS
		if (received == 0 || received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break; /* some servers seem to ignore this part of the specification (v0.16.1): "As per RFCs 5246 and 8446, Gemini servers MUST send a TLS `close_notify`" */
		mbedtls_strerror(received, errbuf, sizeof(errbuf));
		error("failed to download `%s`: %s", sel->url, errbuf);
#else
		if (received == 0 || SSL_get_error(ssl, received) == SSL_ERROR_ZERO_RETURN) break; /* some servers seem to ignore this part of the specification (v0.16.1): "As per RFCs 5246 and 8446, Gemini servers MUST send a TLS `close_notify`" */
		error("failed to download `%s`: %s", sel->url, ERR_reason_error_string(ERR_get_error()));
#endif
		goto fail;
	}
	if (total > 2048 && interactive) fputc('\n', stderr);

	*mime = str_copy(meta);

	ret = (data[0] - '0') * 10 + (data[1] - '0');

fail:
	free(data);
#ifdef GPLACES_USE_MBEDTLS
	mbedtls_ssl_free(&ssl);
#else
	if (cert) X509_free(cert);
	if (ssl) SSL_free(ssl);
	else if (bio) BIO_free(bio);
#endif
	if (fd != -1) close(fd);
	return ret;
}


static void sigint(int sig) {
	(void)sig;
}


static int download(Selector *sel, FILE *fp, char **mime, int ask) {
	struct sigaction sa = {.sa_handler = sigint}, old;
	int status, redirs = 0, ret = 40;

#ifdef GPLACES_USE_MBEDTLS
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) goto out;
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) goto out;
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
#else
	SSL_CTX *ctx;
	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) goto out;
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);
#endif
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, &old);

	do {
#ifdef GPLACES_USE_MBEDTLS
		status = do_download(sel, &conf, fp, mime, ask);
#else
		status = do_download(sel, ctx, fp, mime, ask);
#endif
		if ((ret = (status >= 20 && status <= 29))) break;
		free(*mime); *mime = NULL;
	} while ((status >= 10 && status <= 19) || (status >= 30 && status <= 39 && ++redirs < 5));

	sigaction(SIGINT, &old, NULL);

out:
#ifdef GPLACES_USE_MBEDTLS
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_config_free(&conf);
#else
	if (ctx) SSL_CTX_free(ctx);
#endif

	if (redirs == 5) error("too many redirects from `%s`", sel->url);
	return ret;
}


static void download_to_file(Selector *sel) {
	static char suggestion[1024];
	FILE *fp;
	char *mime = NULL, *filename, *def, *download_dir;
	int ret;

	def = strrchr(sel->path, '/');
	if (*def == '/') ++def;
	if (!*def) def = sel->repr;
	if ((download_dir = set_var(&variables, "DOWNLOAD_DIRECTORY", NULL)) == NULL) download_dir = ".";
	snprintf(suggestion, sizeof(suggestion), "%s/%s", download_dir, def);

	if ((filename = read_line("enter filename (press ENTER for `%s`): ", suggestion)) == NULL) return;
	if (!strlen(filename)) filename = suggestion;
	if ((fp = fopen(filename, "wb")) == NULL) {
		error("cannot create file `%s`: %s", filename, strerror(errno));
		return;
	}
	ret = download(sel, fp, &mime, 1);
	fclose(fp);
	free(mime);
	if (fp && !ret) unlink(filename);
}


static SelectorList download_to_temp(Selector *sel, int ask, int gemtext) {
	static char filename[1024], template[1024];
	FILE *fp;
	const char *tmpdir, *handler;
	SelectorList list = LIST_HEAD_INITIALIZER(list);
	char *mime = NULL;
	int fd;

	if ((tmpdir = getenv("TMPDIR")) == NULL) tmpdir = "/tmp/";
	snprintf(template, sizeof(template), "%sgplaces.XXXXXXXX", tmpdir);
	snprintf(filename, sizeof(filename), "%s", template);
	if ((fd = mkstemp(filename)) == -1 || (fp = fdopen(fd, "r+w")) == NULL) {
		error("cannot create temporary file: %s", strerror(errno));
		goto out;
	}
	if (!download(sel, fp, &mime, ask) || fflush(fp) == EOF) goto out;
	if (!strncmp(mime, "text/gemini", 11)) {
		if (fseek(fp, 0, SEEK_SET) == -1) goto out;
		list = parse_gemtext(sel, fp);
	} else if (!gemtext && (handler = find_mime_handler(mime)) != NULL) execute_handler(handler, filename, sel);

out:
	if (*filename) unlink(filename);
	free(mime);
	if (fp) fclose(fp);
	return list;
}


/*============================================================================*/
static int ndigits(int n) {
	int digits = 0;
	for ( ; n > 0; n /= 10, ++digits);
	return digits;
}


static void print_raw(FILE *fp, SelectorList *list, const char *filter) {
	regex_t re;
	Selector *sel;

	if (filter && regcomp(&re, filter, REG_NOSUB) != 0) filter = NULL;

	SIMPLEQ_FOREACH(sel, list, next)
		if (!filter || regexec(&re, sel->raw, 0, NULL, 0) == 0) fprintf(fp, "%s\n", sel->raw);

	if (filter) regfree(&re);
}


static void print_gemtext(FILE *fp, SelectorList *list, const char *filter) {
	regex_t re;
	Selector *sel;
	int length, out, rem;
	const char *p;

	if (!interactive) return print_raw(fp, list, filter);

	if (filter && regcomp(&re, filter, REG_NOSUB) != 0) filter = NULL;
	length = get_terminal_width();

	SIMPLEQ_FOREACH(sel, list, next) {
		if (filter && regexec(&re, sel->raw, 0, NULL, 0) != 0) continue;
		rem = (int)strlen(sel->repr);
		if (rem == 0) { fputc('\n', fp); continue; }
		for (p = sel->repr; rem > 0; rem -= out, p += out) {
			out = rem < length ? rem : length;
			switch (sel->type) {
				case 'l':
					if (p == sel->repr) {
						if (out == length) out -= 3 + ndigits(sel->index);
						fprintf(fp, "\33[4;36m(\33[1m%d) %.*s\33[0m\n", sel->index, out, p);
					} else printf("\33[4;36m%.*s\33[0m\n", out, p);
					break;
				case '#':
				case 'i': fprintf(fp, "%.*s\n", out, p); break;
				case '`':
					out = rem;
					fprintf(fp, "%s\n", p);
					break;
				case '>':
					if (out == length) out -= 2;
					fprintf(fp, "%c %.*s\n", sel->type, out, p);
					break;
				default:
					if (out == length) out -= 2;
					if (p == sel->repr) fprintf(fp, "%c %.*s\n", sel->type, out, p);
					else fprintf(fp, "  %.*s\n", out, p);
			}
		}
	}

	if (filter) regfree(&re);
}


static void page_gemtext(SelectorList *list) {
	int fds[2];
	FILE *fp;
	pid_t pid;
	const char *pager;

	if ((pager = set_var(&variables, "PAGER", NULL)) == NULL && (pager = getenv("PAGER")) == NULL) pager = "less -r";
	if (!strcmp(pager, "cat")) return;

	if (pipe(fds) < 0) return;
	if ((pid = fork()) == 0) {
		close(fds[1]);
		dup2(fds[0], STDIN_FILENO);
		close(fds[0]);
		execl("/bin/sh", "sh", "-c", pager, (char *)NULL);
		exit(EXIT_FAILURE);
	} else if (pid < 0) return;

	close(fds[0]);

	if ((fp = fdopen(fds[1], "w")) != NULL) {
		print_gemtext(fp, list, NULL);
		fclose(fp);
	}

	reap(pager, pid);
}


static void show_gemtext(SelectorList *list, const char *filter) {
	int lines = 0, height;
	Selector *it;
	if (!filter && interactive) {
		SIMPLEQ_FOREACH(it, list, next) ++lines;
		height = get_terminal_height();
		if (lines > height) page_gemtext(list);
	}
	print_gemtext(stdout, list, filter);
}


static void navigate(Selector *to) {
	const char *handler = NULL;
	SelectorList new = SIMPLEQ_HEAD_INITIALIZER(new);
	FILE *fp;
	size_t len;
#ifdef GPLACES_USE_LIBMAGIC
	magic_t mag;
	const char *mime = NULL;
#endif

	if (!strcmp(to->scheme, "file")) {
		if ((len = strlen(to->path)) >= 4 && !strcmp(&to->path[len - 4], ".gmi")) {
			if ((fp = fopen(to->path, "r")) == NULL) return;
			new = parse_gemtext(to, fp);
			fclose(fp);
		} else {
#ifdef GPLACES_USE_LIBMAGIC
			if ((mag = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS)) == NULL) return;
			if (magic_load(mag, NULL) == 0) mime = magic_file(mag, to->path);
			if (mime) handler = find_mime_handler(mime);
			magic_close(mag);
#else
			error("unable to detect the MIME type of %s", to->path);
#endif
			goto handle;
		}
	} else if (strcmp(to->scheme, "gemini")) {
		handler = find_mime_handler(to->scheme);
		goto handle;
	} else new = download_to_temp(to, 1, 0);

	if (SIMPLEQ_EMPTY(&new)) return;
	snprintf(prompt, sizeof(prompt), "(\33[35m%s\33[0m)> ", to->url);
	free_selectors(&menu);
	menu = new;
	return show_gemtext(&new, NULL);

handle:
	if (handler) execute_handler(handler, to->url, to);
}


static void edit_variable(VariableList *vars, char *line) {
	char *name = next_token(&line);
	char *data = next_token(&line);

	if (name != NULL) {
		if (data) set_var(vars, name, "%s", data);
		else puts(set_var(vars, name, NULL));
	} else {
		Variable *it;
		LIST_FOREACH(it, vars, next) printf("%s = \"%s\"\n", it->name, it->data);
	}
}


/*============================================================================*/
static const Help gemini_help[] = {
	{
		"alias",
		"ALIAS [<name>] [<value>]" \
	},
	{
		"authors",
		"Dima Krasner <dima@dimakrasner.com>\n" \
		"Sebastian Steinhauer <s.steinhauer@yahoo.de>" \
	},
	{
		"back",
		"BACK" \
	},
	{
		"bookmarks",
		"BOOKMARKS [<filter>]/[<item-id>]" \
	},
	{
		"commands",
		"alias         bookmarks     go            help          open\n" \
		"quit          save          see           set           show\n" \
		"subscriptions type"
	},
	{
		"help",
		"HELP [<topic>]" \
	},
	{
		"license",
		"gplaces - a simple terminal Gemini client\n" \
		"Copyright (C) 2022  Dima Krasner\n" \
		"Copyright (C) 2019  Sebastian Steinhauer\n" \
		"\n" \
		"This program is free software: you can redistribute it and/or modify\n" \
		"it under the terms of the GNU General Public License as published by\n" \
		"the Free Software Foundation, either version 3 of the License, or\n" \
		"(at your option) any later version.\n" \
		"\n" \
		"This program is distributed in the hope that it will be useful,\n" \
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n" \
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n" \
		"GNU General Public License for more details.\n" \
		"\n" \
		"You should have received a copy of the GNU General Public License\n" \
		"along with this program.  If not, see <https://www.gnu.org/licenses/>." \
	},
	{
		"open",
		"OPEN <url>" \
	},
	{
		"go",
		"GO <url>" \
	},
	{
		"quit",
		"QUIT" \
	},
	{
		"save",
		"SAVE <item-id>" \
	},
	{
		"see",
		"SEE <item-id>" \
	},
	{
		"set",
		"SET [<name>] [<value>]" \
	},
	{
		"show",
		"SHOW [<filter>]" \
	},
	{
		"type",
		"TYPE [<name>] [<value>]" \
	},
	{
		"variables",
		"HOME_CAPSULE - the Gemini URL which will be opened on startup\n" \
		"DOWNLOAD_DIRECTORY - the directory which will be default for downloads" \
	},
	{ NULL, NULL }
};


/*============================================================================*/
static void cmd_quit(char *line) {
	(void)line;
	exit(EXIT_SUCCESS);
}


static void cmd_open(char *line) {
	const char *url;
	if ((url = next_token(&line)) == NULL || *url == '\0') return;
	Selector *to = new_selector('l', url);
	if (parse_url(NULL, to, url)) navigate(to);
	free_selector(to);
}


static void cmd_show(char *line) {
	show_gemtext(&menu, next_token(&line));
}


static void cmd_save(char *line) {
	Selector *to = find_selector(&menu, line);
	if (to) download_to_file(to);
}


static void cmd_help(char *line) {
	int i;
	const Help *help;
	char *topic = next_token(&line);

	if (topic) {
		for (help = gemini_help; help->name; ++help) {
			if (!strcasecmp(help->name, topic)) {
				if (help->text) puts(help->text);
				else printf("sorry topic `%s` has no text yet :(\n", topic);
				return;
			}
		}
	}

	puts("available topics, type `help <topic>` to get more information");
	for (i = 1, help = gemini_help; help->name; ++help, ++i) {
		printf("%-13s ", help->name);
		if (i % 5 == 0) puts("");
	}
	puts("");
}


static void cmd_bookmarks(char *line) {
	Selector *it, *to = find_selector(&bookmarks, line);
	if (to != NULL) navigate(to);
	else {
		char *name = next_token(&line);
		char *url = next_token(&line);
		if (url) {
			Selector *sel = new_selector('l', url);
			if (parse_url(NULL, sel, url)) {
				free(sel->repr);
				sel->repr = str_copy(name);
				sel->index = 1;
				SIMPLEQ_FOREACH(it, &bookmarks, next) ++sel->index;
				SIMPLEQ_INSERT_TAIL(&bookmarks, sel, next);
			}
		} else show_gemtext(&bookmarks, name);
	}
}


static void cmd_subscriptions(char *line) {
	char ts[11];
	SelectorList list, feed = SIMPLEQ_HEAD_INITIALIZER(feed);
	Selector *sel, *it, *copy;
	struct tm *tm;
	time_t t;
	int index = 1;
	char *url = next_token(&line);
	if (url) {
		Selector *sel = new_selector('l', url);
		if (parse_url(NULL, sel, url)) {
			free(sel->repr);
			sel->repr = str_copy(url);
			SIMPLEQ_INSERT_TAIL(&subscriptions, sel, next);
		}
	} else {
		t = time(NULL);
		tm = gmtime(&t);
		strftime(ts, sizeof(ts), "%Y-%m-%d", tm);

		SIMPLEQ_FOREACH(sel, &subscriptions, next) {
			list = download_to_temp(sel, 0, 1);
			if (SIMPLEQ_EMPTY(&list)) continue;

			copy = new_selector('l', sel->raw);
			if (!parse_url(NULL, copy, sel->url)) { free_selector(copy); continue; }
			copy->index = index++;

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == '#' && (it->raw[1] == ' ' ||  it->raw[1] == '\t')) {
					copy->repr = str_copy(&it->repr[2]);
					break;
				}
			}

			if (!copy->repr) copy->repr = str_copy(sel->repr);
			SIMPLEQ_INSERT_TAIL(&feed, copy, next);

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == 'l' && !strncmp(it->repr, ts, 10)) {
					copy = new_selector('l', it->raw);
					copy->repr = str_copy(it->repr);
					if (!parse_url(NULL, copy, it->url)) { free_selector(copy); continue; }
					copy->index = index++;
					SIMPLEQ_INSERT_TAIL(&feed, copy, next);
				}
			}

			free_selectors(&list);
		}
		if (SIMPLEQ_EMPTY(&feed)) return;
		free_selectors(&menu);
		menu = feed;
		show_gemtext(&feed, NULL);
	}
}


static void cmd_set(char *line) {
	edit_variable(&variables, line);
}


static void cmd_see(char *line) {
	Selector *to = find_selector(&menu, line);
	if (to) puts(to->url);
}


static void cmd_alias(char *line) {
	edit_variable(&aliases, line);
}


static void cmd_type(char *line) {
	edit_variable(&typehandlers, line);
}


static const Command gemini_commands[] = {
	{ "quit", cmd_quit },
	{ "open", cmd_open },
	{ "go", cmd_open },
	{ "show", cmd_show },
	{ "save", cmd_save },
	{ "help", cmd_help },
	{ "bookmarks", cmd_bookmarks },
	{ "subscriptions", cmd_subscriptions },
	{ "set", cmd_set },
	{ "see", cmd_see },
	{ "alias", cmd_alias },
	{ "type", cmd_type },
	{ NULL, NULL }
};


/*============================================================================*/
static void eval(const char *input, const char *filename) {
	static int nested =  0;
	const Command *cmd;
	char *str, *copy, *line, *token, *alias;
	int line_no;

	if (nested >= 10) {
		error("eval() nested too deeply");
		return;
	} else ++nested;

	str = copy = str_copy(input); /* copy input as it will be modified */

	for (line_no = 1; (line = str_split(&str, "\r\n")) != NULL; ++line_no) {
		if ((token = next_token(&line)) != NULL) {
			for (cmd = gemini_commands; cmd->name; ++cmd) {
				if (!strcasecmp(cmd->name, token)) {
					cmd->func(line);
					break;
				}
			}
			if (cmd->name == NULL) {
				if ((alias = set_var(&aliases, token, NULL)) != NULL) eval(alias, token);
				else {
					if (filename == NULL) error("unknown command `%s`", token);
					else error("unknown command `%s` in file `%s` at line %d", token, filename, line_no);
				}
			}
		}
		str = str_skip(str, "\r\n");
	}

	free(copy);
	--nested;
}


static void shell_name_completion(const char *text, bestlineCompletions *lc) {
	static int len;
	const Command *cmd;
	const Variable *alias;

	len = strlen(text);

	for (cmd = gemini_commands; cmd->name; ++cmd)
		if (!strncasecmp(cmd->name, text, len)) bestlineAddCompletion(lc, cmd->name);

	LIST_FOREACH(alias, &aliases, next)
		if (!strncasecmp(alias->name, text, len)) bestlineAddCompletion(lc, alias->name);
}


static void shell() {
	static char path[1024], command[1024];
	const char *home;
	char *line, *base;
	Selector *to = NULL;

	bestlineSetCompletionCallback(shell_name_completion);

	if ((home = getenv("HOME")) != NULL) {
		snprintf(path, sizeof(path), "%s/.gplaces_history", home);
		bestlineHistoryLoad(path);
	}

	eval("open $HOME_CAPSULE", NULL);

	for (;;) {
		if ((line = base = bestline(prompt)) == NULL) break;
		if ((to = find_selector(&menu, line)) != NULL) {
			if (to->url) {
				snprintf(command, sizeof(command), "open %s", to->url);
				bestlineHistoryAdd(command);
			} else bestlineHistoryAdd(line);
			navigate(to);
		} else {
			eval(line, NULL);
			bestlineHistoryAdd(line);
		}
		free(base);
	}

	if (home != NULL) bestlineHistorySave(path);
	bestlineHistoryFree();
}


/*============================================================================*/
static int load_config_file(const char *filename) {
	long length;
	FILE *fp = NULL;
	char *data = NULL;
	int ret = 0;

	if ((fp = fopen(filename, "rb")) == NULL) goto out;
	if (fseek(fp, 0, SEEK_END)) goto out;
	if ((length = ftell(fp)) <= 0) goto out;
	if (fseek(fp, 0, SEEK_SET)) goto out;
	if ((data = malloc(length + 1)) == NULL) goto out;
	if (fread(data, 1, length, fp) != (size_t)length) goto out;
	data[length] = '\0';

	eval(data, filename);
	ret = 1;

out:
	free(data);
	if (fp) fclose(fp);
	return ret;
}


static void load_config_files() {
	static char buffer[1024];
	char *home;

	if ((home = getenv("HOME")) != NULL) {
		snprintf(buffer, sizeof(buffer), "%s/.gplaces.conf", home);
		if (load_config_file(buffer)) return;
	}
	load_config_file(CONFDIR"/gplaces.conf");
}


static void parse_arguments(int argc, char **argv) {
	int ch;
	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
			case 'c':
				load_config_file(optarg);
				break;
			default:
				fprintf(stderr,
					"usage: gplaces [-c config-file] [url]\n"
				);
				exit(EXIT_SUCCESS);
				break;
		}
	}

	argc -= optind; argv += optind;
	if (argc > 0) set_var(&variables, "HOME_CAPSULE", "%s", argv[0]);
}


static void quit_client() {
	free_variables(&variables);
	free_variables(&aliases);
	free_variables(&typehandlers);
	free_selectors(&bookmarks);
	free_selectors(&subscriptions);
	free_selectors(&menu);
	if (interactive) puts("\33[0m");
}


int main(int argc, char **argv) {
	atexit(quit_client);
	setlinebuf(stdout); /* if stdout is a file, flush after every line */

#ifndef GPLACES_USE_MBEDTLS
	SSL_library_init();
	SSL_load_error_strings();
#endif

	interactive = isatty(STDOUT_FILENO);

	load_config_files();
	parse_arguments(argc, argv);

	if (interactive) puts(
		"gplaces - 0.16.0  Copyright (C) 2022  Dima Krasner\n" \
		"Based on delve 0.15.4  Copyright (C) 2019  Sebastian Steinhauer\n" \
		"This program comes with ABSOLUTELY NO WARRANTY; for details type `help license'.\n" \
		"This is free software, and you are welcome to redistribute it\n" \
		"under certain conditions; type `help license' for details.\n" \
		"\n" \
		"Type `help` for help.\n" \
	);

	shell();

	return 0;
}
/* vim: set ts=4 sw=4 noexpandtab: */
