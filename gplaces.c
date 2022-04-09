/*
================================================================================

	gplaces - a simple terminal gemini client
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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <curl/curl.h>

#include "bestline/bestline.h"


/*============================================================================*/
typedef struct Selector {
	struct Selector *next;
	int index;
	char type, *name, *scheme, *host, *port, *path, *url, *mime;
	CURLU *cu;
} Selector;

typedef struct Variable {
	struct Variable *next;
	char *name, *data;
} Variable;

typedef struct Command {
	const char *name;
	void (*func)(char *line);
} Command;

typedef struct Help {
	const char *name;
	const char *text;
} Help;

typedef struct Response {
	char filename[1024];
	char *mime;
	FILE *fp;
	char *buffer;
	size_t length;
} Response;


/*============================================================================*/
Variable *variables = NULL;
Variable *aliases = NULL;
Variable *typehandlers = NULL;
Selector *bookmarks = NULL;
Selector *history = NULL;
Selector *menu = NULL;


/*============================================================================*/
const char *find_mime_handler(const char *mime);
void execute_handler(const char *handler, const char *filename, Selector *to);


/*============================================================================*/
void vlogf(const char *color, const char *fmt, va_list va) {
	printf("\33[%sm", color);
	vprintf(fmt, va);
	puts("\33[0m");
}

void info(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	vlogf("34", fmt, va);
	va_end(va);
}

void error(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	vlogf("31", fmt, va);
	va_end(va);
}

void panic(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	vlogf("31", fmt, va);
	va_end(va);
	exit(EXIT_FAILURE);
}


/*============================================================================*/
void str_free(char *str) {
	free(str);
}

char *str_copy(const char *str) {
	char *new;
	if ((new = strdup(str)) == NULL) panic("cannot allocate new string");
	return new;
}

char *str_skip(char *str, const char *delim) {
	while (*str && strchr(delim, *str)) ++str;
	return str;
}

char *str_split(char **str, const char *delim) {
	char *begin;
	if (*str == NULL || **str == '\0') return NULL;
	for (begin = *str; *str && !strchr(delim, **str); ++*str) ;
	if (**str != '\0') { **str = '\0'; ++*str; }
	return begin;
}

char *str_next(char **str, const char *delims) {
	char *begin;
	if (*str == NULL || **str == '\0') return NULL;
	begin = *str + strspn(*str, delims);
	*str = begin + strcspn(begin, delims);
	if (**str != '\0') { **str = '\0'; ++*str; }
	return begin;
}

int str_contains(const char *haystack, const char *needle) {
	const char *a, *b;
	for (; *haystack; ++haystack) {
		for (a = haystack, b = needle; *a && *b; ++a, ++b) {
			if (tolower(*a) != tolower(*b)) break;
		}
		if (*b == '\0') return 1;
	}
	return 0;
}


/*============================================================================*/
void free_variable(Variable *var) {
	while (var) {
		Variable *next = var->next;
		str_free(var->name);
		str_free(var->data);
		free(var);
		var = next;
	}
}


char *set_var(Variable **list, const char *name, const char *fmt, ...) {
	Variable *var;

	if (name == NULL) return NULL;
	for (var = *list; var; var = var->next) {
		if (!strcasecmp(var->name, name)) break;
	}

	if (fmt) {
		va_list va;
		char buffer[1024];

		va_start(va, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, va);
		va_end(va);

		if (var == NULL) {
			if ((var = malloc(sizeof(Variable))) == NULL) panic("cannot allocate new variable");
			var->next = *list;
			var->name = str_copy((char*)name);
			var->data = str_copy(buffer);
			*list = var;
		} else {
			str_free(var->data);
			var->data = str_copy(buffer);
		}
	}

	return var ? var->data : NULL;
}


int get_var_boolean(const char *name) {
	char *data = set_var(&variables, name, NULL);
	return data ? (!strcasecmp(data, "on") || !strcasecmp(data, "true")) : 0;
}


int get_var_integer(const char *name, int def) {
	int value;
	char *data = set_var(&variables, name, NULL);
	if (data == NULL || sscanf(data, "%d", &value) != 1) return def;
	return value;
}


/*============================================================================*/
Selector *new_selector() {
	Selector *new = calloc(1, sizeof(Selector));
	if (new == NULL) panic("cannot allocate new selector");
	return new;
}

void free_selector(Selector *sel) {
	while (sel) {
		Selector *next = sel->next;
		str_free(sel->name);
		curl_free(sel->scheme);
		curl_free(sel->host);
		curl_free(sel->port);
		curl_free(sel->path);
		curl_free(sel->url);
		if (sel->cu) curl_url_cleanup(sel->cu);
		free(sel);
		sel = next;
	}
}


int set_selector_url(Selector *sel, const char *url) {
	if ((curl_url_set(sel->cu, CURLUPART_URL, url, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_SCHEME, &sel->scheme, 0) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_HOST, &sel->host, 0) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_PATH, &sel->path, 0) != CURLUE_OK)) return 0;

	switch (curl_url_get(sel->cu, CURLUPART_PORT, &sel->port, 0)) {
	case CURLUE_OK: break;
	case CURLUE_NO_PORT: sel->port = str_copy("1965"); break;
	default: free_selector(sel); return 0;
	}

	return 1;
}


Selector *copy_selector(Selector *sel) {
	Selector *new = new_selector();
	new->next = NULL;
	new->index = 1;
	new->type = sel->type;
	new->name = str_copy(sel->name);
	if (sel->cu && ((new->cu = curl_url_dup(sel->cu)) == NULL) | !set_selector_url(new, new->url)) panic("cannot copy selector URL");
	return new;
}


Selector *append_selector(Selector *list, Selector *sel) {
	if (list == NULL) {
		sel->next = NULL;
		sel->index = 1;
		return sel;
	} else {
		Selector *it;
		for (it = list; it->next; it = it->next) ;
		it->next = sel;
		sel->next = NULL;
		sel->index = it->index + 1;
		return list;
	}
}


Selector *prepend_selector(Selector *list, Selector *sel) {
	sel->next = list;
	sel->index = list ? list->index + 1 : 1;
	return sel;
}


Selector *find_selector(Selector *list, const char *line) {
	int index;
	if ((index = atoi(line)) <= 0) return NULL;
	for (; list; list = list->next) if (list->index == index) return list;
	return NULL;
}


Selector *parse_selector(Selector *from, char *str) {
	static char buffer[1024];
	char *url = str;
	Selector *sel;

	if (str == NULL || *str == '\0') return NULL;

	if (!from && strncmp(url, "gemini://", 9)) {
		snprintf(buffer, sizeof(buffer), "gemini://%s", url);
		url = buffer;
	}

	sel = new_selector();
	sel->type = '1';
	sel->name = str_copy(str);
	sel->cu = (from && from->cu) ? curl_url_dup(from->cu) : curl_url();
	if (!sel->cu || !set_selector_url(sel, url)) {
		free_selector(sel);
		return NULL;
	}

	return sel;
}


Selector *parse_selector_list(Selector *from, char *str) {
	char *line, *url;
	Selector *list = NULL, *sel;
	int pre = 0;

	while ((line = str_split(&str, "\n")) != NULL) {
		if (strncmp(line, "```", 3) == 0) {
			pre = !pre;
			continue;
		}

		if (pre) {
			sel = new_selector();
			sel->type = '`';
			sel->name = str_copy(line);
		} else if (line[0] == '=' && line[1] == '>') {
			line += 2;
			url = str_next(&line, " \t\r\n");
			sel = parse_selector(from, url);
			if (!sel) continue; // TODO
			if (*line) {
				free(sel->name);
				sel->name = str_copy(*line ? line : url);
			}
		} else if (*line == '#') {
			sel = new_selector();
			sel->type = 't';
			sel->name = str_copy(line);
		} else if (strncmp(line, "```", 3) == 0)
			pre = !pre;
		else {
			sel = new_selector();
			sel->type = 'i';
			sel->name = str_copy(line);
		}

		list = append_selector(list, sel);

		str = str_skip(str, "\r");
		str = str_skip(str, "\n");
	}

	return list;
}


/*============================================================================*/
char *next_token(char **str) {
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


char *read_line(const char *fmt, ...) {
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


int get_terminal_height() {
	struct winsize wz;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &wz);
	return wz.ws_row - 2; /* substract 2 lines (1 for tmux etc., 1 for the prompt) */
}


int show_pager_stop() {
	char buffer[256], *line;

	printf("\33[0;32m-- press RETURN to continue (or 'q' and return to quit) --\33[0m");
	fflush(stdout);
	if ((line = fgets(buffer, sizeof(buffer), stdin)) == NULL) return 1;
	line = str_skip(line, " \t\v");
	return line[0] == 'q' || line[0] == 'Q';
}


void print_text(const char *text) {
	char *copy, *str, *line, *p;
	int i, pages, height, length;

	height = get_terminal_height();
	pages = get_var_boolean("PAGE_TEXT");
	length = get_var_integer("LINE_LENGTH", 120);

	copy = str = str_copy(text);
	for (i = 0; (line = str_split(&str, "\n")) != NULL; ++i) {
		for (p = line; *p; ++p) if (*p == '\r') *p = '\0'; /* remove any CR */
		printf("%.*s\n", length, line);
		if (pages && i >= height) { if (show_pager_stop()) break; i = 0; }
		str = str_skip(str, "\r"); /* just skip CR so we can show empty lines */
	}
	str_free(copy);
}


/*============================================================================*/


static int tofu(X509 *cert) {
	static char hosts[1024], buffer[2048], namebuf[1024];
	X509_NAME *name;
	const char *home;
	EVP_PKEY *pub;
	char *p, *hex, *line;
	size_t len, hlen;
	FILE *fp;
	BIGNUM *bn;
	int trust = 1, namelen;

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

	if ((home = getenv("HOME")) == NULL) return 0;
	snprintf(hosts, sizeof(hosts), "%s/.gplaces_hosts", home);
	if ((fp = fopen(hosts, "r")) != NULL) {
		while ((line = fgets(buffer, sizeof(buffer), fp)) != NULL) {
			if (strncmp(line, namebuf, namelen)) continue;
			if (line[namelen] != ' ') continue;
			trust = (strncmp(&line[namelen + 1], hex, hlen) == 0) && (line[namelen + 1 + hlen] == '\n');
			goto out;
		}

		fclose(fp); fp = NULL;
	}

	if (trust) trust = (((fp = fopen(hosts, "a")) != NULL) && (fprintf(fp, "%s %s\n", namebuf, hex) > 0));

out:
	if (fp) fclose(fp);
	OPENSSL_free(hex);
	return trust;
}


static int do_download(Selector *sel, SSL_CTX *ctx, int (*cb)(Selector *, const char *, const char *, size_t, void *), void *arg) {
	struct addrinfo hints, *result, *it;
	char request[1024], prompt[256], *data = NULL, *crlf, *meta, *line;
	struct timeval tv = {.tv_sec = 15};
	size_t total, cap = 2 + 1 + 1024 + 2 + 1;
	int fd = -1, received, ret = 40;
	BIO *bio = NULL;
	SSL *ssl = NULL;
	X509 *cert = NULL;

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

	if (((ssl = SSL_new(ctx)) == NULL) || ((bio = BIO_new_socket(fd, BIO_NOCLOSE)) == NULL)) {
		error("cannot establish secure connection to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}
 
	SSL_set_tlsext_host_name(ssl, sel->host);
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);

	if ((SSL_do_handshake(ssl) != 1) || ((cert = SSL_get_peer_certificate(ssl)) == NULL)) {
		error("cannot establish secure connection to `%s`:`%s`: %s", sel->host, sel->port, ERR_reason_error_string(ERR_get_error()));
		goto fail;
	}

	if (!tofu(cert)) {
		error("cannot establish secure connection to `%s`:`%s`: certificate has changed", sel->host, sel->port);
		goto fail;
	}

	snprintf(request, sizeof(request), "%s\r\n", sel->url);
	if (SSL_write(ssl, request, strlen(request)) == 0) {
		error("cannot send request to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}

	if ((data = malloc(cap)) == NULL) panic("cannot allocate download data");

	for (total = 0; total < cap - 1 && (total < 5 || (data[total - 2] != '\r' && data[total - 1] != '\n')); ++total) {
		if ((received = SSL_read(ssl, &data[total], 1)) > 0) continue;
		if ((received == 0) || (SSL_get_error(ssl, received) == SSL_ERROR_ZERO_RETURN)) break;
		error("failed to download `%s`: %s", sel->url, ERR_reason_error_string(ERR_get_error()));
		goto fail;
	}
	if (data[1] < '0' || data[0] > '9' || data[1] < '0' || data[1] > '9' || data[2] != ' ' || data[total - 2] != '\r' || data[total - 1] != '\n') goto fail;
	data[total] = '\0';

	cap = 1024 * 64;
	if ((data = realloc(data, cap)) == NULL) panic("cannot allocate download data");

	crlf = &data[total - 2];
	*crlf = '\0';
	meta = &data[3];
	if (meta >= crlf) meta = "";

	for (;;) {
		if ((received = SSL_read(ssl, crlf + 1, cap - (crlf - data) - 1)) > 0) {
			if (!cb(sel, meta, crlf + 1, received, arg)) goto fail;
			total += received;
			if (total > (1024 * 256)) printf("downloading %.2f kb...\r", (double)total / 1024.0);
			continue;
		}
		if ((received == 0) || (SSL_get_error(ssl, received) == SSL_ERROR_ZERO_RETURN)) break; /* some servers seem to ignore this part of the specification (v0.16.1): "As per RFCs 5246 and 8446, Gemini servers MUST send a TLS `close_notify`" */
		error("failed to download `%s`: %s", sel->url, ERR_reason_error_string(ERR_get_error()));
		goto fail;
	}
	if (total > (1024 * 256)) puts("");

	SSL_free(ssl); ssl = NULL; bio = NULL;

	switch (data[0]) {
	case '2':
		if (!*meta) goto fail;
		break;

	case '1':
		if (!*meta) goto fail;
		snprintf(prompt, sizeof(prompt), "(\33[35m%s\33[0m)> ", meta);
		if ((line = bestline(prompt)) == NULL) goto fail;
		bestlineHistoryAdd(line);
		if ((curl_url_set(sel->cu, CURLUPART_QUERY, line, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK)) { free(line); goto fail; }
		free(line);
		break;

	case '3':
		if (!*meta) goto fail;
		if ((curl_url_set(sel->cu, CURLUPART_URL, meta, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) || (curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK)) goto fail;
		break;

	default:
		error("failed to download `%s`: %s", sel->url, *meta ? meta : data);
	}

	ret = (data[0] - '0') * 10 + (data[1] - '0');

fail:
	if (data) free(data);
	if (cert) X509_free(cert);
	if (ssl) SSL_free(ssl);
	else if (bio) BIO_free(bio);
	if (fd != -1) close(fd);
	return ret;
}


int download(Selector *sel, int (*cb)(Selector *, const char *, const char *, size_t, void *), void *arg) {
	SSL_CTX *ctx = NULL;
	int status, redirs = 0;

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) return 40;

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);

	do {
		status = do_download(sel, ctx, cb, arg);
	} while ((status >= 10 && status <= 19) || (status >= 30 && status <= 39 && ++redirs < 5));

	SSL_CTX_free(ctx);

	if (redirs == 5) error("too many redirects from `%s`", sel->url);
	return (status >= 20 && status <= 29) ? 1 : 0;
}


static int append_to_file(Selector *sel, const char *meta, const char *buffer, size_t len, void *arg) {
	size_t total = 0, out;
	Response *r = (Response *)arg;

	(void)sel;

	if ((r->mime == NULL) && ((r->mime = strdup(meta)) == NULL)) return 0;

	do {
		if ((out = fwrite(&buffer[total], 1, len - total, r->fp)) == 0) return 0;
		total += out;
	} while (total < len);

	return 1;
}


void download_to_file(Selector *sel) {
	Response r = {0};
	char *filename, *def, *download_dir, suggestion[1024];
	int ret;

	def = strrchr(sel->path, '/');
	if (*def == '/') ++def;
	if (!*def) def = sel->name;
	if ((download_dir = set_var(&variables, "DOWNLOAD_DIRECTORY", NULL)) == NULL) download_dir = ".";
	snprintf(suggestion, sizeof(suggestion), "%s/%s", download_dir, def);

	if ((filename = read_line("enter filename (press ENTER for `%s`): ", suggestion)) == NULL) return;
	if (!strlen(filename)) filename = suggestion;
	if ((r.fp = fopen(filename, "wb")) == NULL) {
		error("cannot create file `%s`: %s", filename, strerror(errno));
		return;
	}
	ret = download(sel, append_to_file, &r);
	fclose(r.fp);
	free(r.mime);
	if (r.fp && !ret) unlink(filename);
}


static int append_by_type(Selector *sel, const char *meta, const char *buffer, size_t len, void *arg) {
	static char template[1024];
	const char *tmpdir;
	size_t total, out;
	FILE *fp;
	int fd;
	Response *r = (Response *)arg;

	(void)sel;

	if (r->mime == NULL) {
		if ((r->mime = strdup(meta)) == NULL) return 0;
		if (strncmp(r->mime, "text/gemini", 11)) {
			if (fflush(r->fp) == EOF) return 0;

			if ((tmpdir = getenv("TMPDIR")) == NULL) tmpdir = "/tmp/";
			snprintf(template, sizeof(template), "%sgplaces.XXXXXXXX", tmpdir);
			snprintf(r->filename, sizeof(r->filename), "%s", template);
			if (((fd = mkstemp(r->filename)) == -1) || ((fp = fdopen(fd, "w")) == NULL)) {
				error("cannot create temporary file: %s", strerror(errno));
				return 0;
			}
			for (total = 0; total < r->length; total += out)
				if ((out = fwrite(&r->buffer[total], 1, r->length - total, r->fp)) == 0) return 0;
			fclose(r->fp);
			r->fp = fp;
		}
	}

	for (total = 0; total < len; total += out)
		if ((out = fwrite(&buffer[total], 1, len - total, r->fp)) == 0) return 0;

	return 1;
}


Selector *download_to_menu(Selector *sel) {
	Response r = {0};
	Selector *list = NULL;
	const char *handler;
	
	if ((r.fp = open_memstream(&r.buffer, &r.length)) == NULL) return NULL;
	if (!download(sel, append_by_type, &r)) goto out;
	if (fflush(r.fp) == EOF) goto out;
	if (!strncmp(r.mime, "text/gemini", 11)) list = parse_selector_list(sel, r.buffer);
	else if ((handler = find_mime_handler(r.mime)) != NULL) execute_handler(handler, r.filename, sel);

out:
	if (*r.filename) unlink(r.filename);
	free(r.mime);
	if (r.fp) fclose(r.fp);
	free(r.buffer);
	return list;
}


/*============================================================================*/


void print_menu(Selector *list, const char *filter) {
	int i, height, pages, length, out, rem;
	const char *p;

	height = get_terminal_height();
	pages = get_var_boolean("PAGE_TEXT");
	length = get_var_integer("LINE_LENGTH", 128);

	for (i = 0; list; list = list->next) {
		if (filter && !str_contains(list->name, filter) && (!list->path || !str_contains(list->path, filter))) continue;
		for (rem = (int)strlen(list->name), p = list->name; rem > 0; rem -= out, p += out) {
			switch (list->type) {
				case 'i': out = printf("%.*s", rem < length ? rem : length, p); break;
				case '1':
					if (p == list->name) out = printf("\33[1m%4d\33[0m | \33[4;36m%.*s\33[0m", list->index, rem < length ? rem : length, p);
					else out = printf("     | \33[4;36m%.*s\33[0m", rem < length ? rem : length, p);
					break;
				case 't': out = printf("%.*s", rem < length ? rem : length, p); break;
				case '`': out = (int)fwrite(p, 1, rem, stdout); break;
			}
			putchar('\n'); 
			if (pages && ++i >= height) { if (show_pager_stop()) break; i = 0; }
		}
	}
}


const char *find_mime_handler(const char *mime) {
	const char *handler = set_var(&typehandlers, mime, NULL);
	if (!handler)
		printf("no handler for `%s`\n", mime);
	return handler;
}


void execute_handler(const char *handler, const char *filename, Selector *to) {
	char command[1024];
	size_t l;
	pid_t pid, ret;
	int fd, status;

	for (l = 0; *handler && l < sizeof(command) - 1; ) {
		if (handler[0] == '%' && handler[1] != '\0') {
			const char *append = "";
			switch (handler[1]) {
				case '%': append = "%"; break;
				case 's': append = to->scheme; break;
				case 'h': append = to->host; break;
				case 'p': append = to->port; break;
				case 'P': append = to->path; break;
				case 'n': append = to->name; break;
				case 'u': append = to->url; break;
				case 'f': append = filename; break;
			}
			handler += 2;
			while (*append && l < sizeof(command) - 1) command[l++] = *append++;
		} else command[l++] = *handler++;
	}
	command[l] = '\0';

	pid = fork();
	if (pid == 0) {
		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
			execl("/bin/sh", "sh", "-c", command, (char *)NULL);
		}
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		for (;;) {
			ret = waitpid(pid, &status, 0);
			if (ret < 0 && errno == EAGAIN) continue;
			if ((ret == pid) && WIFEXITED(status))
				printf("`%s` has exited with exit status %d\n", command, WEXITSTATUS(status));
			else if ((ret == pid) && !WIFEXITED(status))
				printf("`%s` has exited abnormally\n", command);
			break;
		}
	} else error("could not execute `%s`", command);
}


void navigate(Selector *to) {
	const char *handler;

	if (to->type != '1') return;

	if (to->url && strncmp(to->url, "gemini://", 9)) {
		if ((handler = find_mime_handler(to->scheme)) == NULL) return;
		execute_handler(handler, to->url, to);
		return;
	}

	Selector *new = download_to_menu(to);
	if (new == NULL) return;
	if (history != to) history = prepend_selector(history, copy_selector(to));
	free_selector(menu);
	print_menu(new, NULL);
	menu = new;
}


void edit_variable(Variable **vars, char *line) {
	char *name = next_token(&line);
	char *data = next_token(&line);

	if (name != NULL) {
		if (data) set_var(vars, name, "%s", data);
		else puts(set_var(vars, name, NULL));
	} else {
		Variable *it;
		for (it = *vars; it; it = it->next) printf("%s = \"%s\"\n", it->name, it->data);
	}
}


/*============================================================================*/
static const Help gemini_help[] = {
	{
		"alias",
		"Syntax:\n" \
		"\tALIAS [<name>] [<value>]\n" \
		"\n" \
		"Description:\n" \
		"\tIf no <name> is given it will show all aliases.\n" \
		"\tWhen <name> is given it will show this specific alias.\n" \
		"\tWhen both <name> and <value> are defined as new alias is created.\n" \
		"\n" \
		"Examples:\n" \
		"\talias b back # create a shorthand for back\n" \
	},
	{
		"authors",
		"Credit goes to the following people:\n\n" \
		"\tDima Krasner <dima@dimakrasner.com>\n" \
		"\tSebastian Steinhauer <s.steinhauer@yahoo.de>\n" \
	},
	{
		"back",
		"Syntax:\n" \
		"\tBACK\n" \
		"\n" \
		"Description:\n" \
		"\tGo back in history.\n" \
	},
	{
		"bookmarks",
		"Syntax:\n" \
		"\tBOOKMARKS [<filter>]/[<item-id>]\n" \
		"\n" \
		"Description:\n" \
		"\tShow all defined bookmarks. If a <filter> is specified, it will\n" \
		"\tshow all selectors containing the <filter> in name or path.\n" \
		"\tIf <item-id> is specified, navigate to the given <item-id>\n" \
		"\tfrom bookmarks.\n" \
		"\n\n" \
		"Syntax:\n" \
		"\tBOOKMARKS <name> <url>\n" \
		"\n" \
		"Description:\n" \
		"\tDefine a new bookmark with the given <name> and <url>.\n" \
	},
	{
		"commands",
		"available commands\n" \
		"alias         back          bookmarks     go            help\n" \
		"history       open          quit          save          see\n" \
		"set           show          type\n"
	},
	{
		"help",
		"Syntax:\n" \
		"\tHELP [<topic>]\n" \
		"\n" \
		"Description:\n" \
		"\tShow all help topics or the help text for a specific <topic>.\n" \
	},
	{
		"history",
		"Syntax:\n" \
		"\tHISTORY [<filter>]/[<item-id>]\n" \
		"\n" \
		"Description:\n" \
		"\tShow the gemini history. If a <filter> is specified, it will\n" \
		"\tshow all selectors containing the <filter> in name or path.\n" \
		"\tIf <item-id> is specified, navigate to the given <item-id>\n" \
		"\tfrom history.\n" \
	},
	{
		"license",
		"gplaces - a simple terminal gemini client\n" \
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
		"along with this program.  If not, see <https://www.gnu.org/licenses/>.\n" \
	},
	{
		"open",
		"Syntax:\n" \
		"\tOPEN <url>\n" \
		"\n" \
		"Description:\n" \
		"\tOpens the given <url>.\n" \
	},
	{
		"go",
		"Syntax:\n" \
		"\tGO <url>\n" \
		"\n" \
		"Description:\n" \
		"\tAlias for open.\n" \
	},
	{
		"quit",
		"Syntax:\n" \
		"\tQUIT\n" \
		"\n" \
		"Description:\n" \
		"\tQuit the gemini client.\n"
	},
	{
		"save",
		"Syntax:\n" \
		"\tSAVE <item-id>\n" \
		"\n" \
		"Description:\n" \
		"\tSaves the given <item-id> from the menu to the disk.\n" \
		"\tYou will be asked for a filename.\n" \
	},
	{
		"see",
		"Syntax:\n" \
		"\tSEE <item-id>\n" \
		"\n" \
		"Description:\n" \
		"\tShow the full gemini URL for the menu selector id.\n" \
	},
	{
		"set",
		"Syntax:\n" \
		"\tSET [<name>] [<value>]\n" \
		"\n" \
		"Description:\n" \
		"\tIf no <name> is given it will show all variables.\n" \
		"\tWhen <name> is given it will show this specific variable.\n" \
		"\tIf <data> is specified the variable will have this value.\n" \
		"\tWhen the variable does not exist the variable will be created.\n" \
	},
	{
		"show",
		"Syntax:\n" \
		"\tSHOW [<filter>]\n" \
		"\n" \
		"Description:\n" \
		"\tShow the current gemini menu. If a <filter> is specified, it will\n" \
		"\tshow all selectors containing the <filter> in name or path.\n"
	},
	{
		"type",
		"Syntax:\n" \
		"\tTYPE [<name>] [<value>]\n" \
		"\n" \
		"Description:\n" \
		"\tIf no <name> is given it will show all type handlers.\n" \
		"\tWhen <name> is given it will show this specific type handler.\n" \
		"\tIf <name> and <value> are defined a new type handler will be installed.\n" \
		"\n" \
		"Examples:\n" \
		"\ttype 0 \"less %f\" # create a type handler for gemini texts\n" \
		"\n" \
		"Format string:\n" \
		"\tThe <value> for type handlers can have the following formating options:\n" \
		"\t%% - simply a `%`\n" \
		"\t%s - scheme\n" \
		"\t%h - hostname\n" \
		"\t%p - port\n" \
		"\t%P - path\n" \
		"\t%n - name\n"
		"\t%u - URL\n" \
		"\t%f - filename\n" \
	},
	{
		"variables",
		"Following variables are used by gplaces:\n" \
		"\tHOME_CAPSULE - the gemini URL which will be opened on startup\n" \
		"\tDOWNLOAD_DIRECTORY - the directory which will be default for downloads\n" \
		"\tPAGE_TEXT - when `on` or `true` menus & text will be paged\n" \
		"\tLINE_LENGTH - defines how long a menu/text line will be displayed\n" \
	},
	{ NULL, NULL }
};


/*============================================================================*/
static void cmd_quit(char *line) {
	(void)line;
	exit(EXIT_SUCCESS);
}


static void cmd_open(char *line) {
	Selector *to = parse_selector(NULL, next_token(&line));
	navigate(to);
	free_selector(to);
}


static void cmd_show(char *line) {
	print_menu(menu, next_token(&line));
}


static void cmd_save(char *line) {
	Selector *to = find_selector(menu, line);
	if (to) download_to_file(to);
}


static void cmd_back(char *line) {
	Selector *to = history ? history->next : NULL;
	(void)line;
	if (to != NULL) {
		history->next = NULL;
		free_selector(history);
		history = to;
		navigate(to);
	} else {
		error("history empty");
	}
}


static void cmd_help(char *line) {
	int i;
	const Help *help;
	char *topic = next_token(&line);

	if (topic) {
		for (help = gemini_help; help->name; ++help) {
			if (!strcasecmp(help->name, topic)) {
				if (help->text) print_text(help->text);
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


static void cmd_history(char *line) {
	Selector *to = find_selector(history, line);
	if (to != NULL) navigate(to);
	else print_menu(history, next_token(&line));
}


static void cmd_bookmarks(char *line) {
	Selector *to = find_selector(bookmarks, line);
	if (to != NULL) navigate(to);
	else {
		char *name = next_token(&line);
		char *url = next_token(&line);
		if (url) {
			Selector *sel = parse_selector(NULL, url);
			if (sel) {
				str_free(sel->name);
				sel->name = str_copy(name);
				bookmarks = append_selector(bookmarks, sel);
			}
		} else print_menu(bookmarks, name);
	}
}


static void cmd_set(char *line) {
	edit_variable(&variables, line);
}


static void cmd_see(char *line) {
	Selector *to = find_selector(menu, line);
	if (to && !strchr("3i", to->type)) puts(to->url);
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
	{ "back", cmd_back },
	{ "help", cmd_help },
	{ "history", cmd_history },
	{ "bookmarks", cmd_bookmarks },
	{ "set", cmd_set },
	{ "see", cmd_see },
	{ "alias", cmd_alias },
	{ "type", cmd_type },
	{ NULL, NULL }
};


/*============================================================================*/
void eval(const char *input, const char *filename) {
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

	str_free(copy);
	--nested;
}


void shell_name_completion(const char *text, bestlineCompletions *lc) {
	static int len;
	const Command *cmd;
	const Variable *alias;

	len = strlen(text);

	for (cmd = gemini_commands; cmd->name; ++cmd)
		if (!strncasecmp(cmd->name, text, len)) bestlineAddCompletion(lc, cmd->name);

	for (alias = aliases; alias; alias = alias->next)
		if (!strncasecmp(alias->name, text, len)) bestlineAddCompletion(lc, alias->name);
}

void shell() {
	char *line, *base, prompt[256];
	Selector *to = NULL;

	bestlineSetCompletionCallback(shell_name_completion);

	eval("open $HOME_CAPSULE", NULL);

	for (;;) {
		snprintf(prompt, sizeof(prompt), "(\33[35m%s\33[0m)> ", history ? history->url : "");
		if ((line = base = bestline(prompt)) == NULL) break;
		bestlineHistoryAdd(line);
		if ((to = find_selector(menu, line)) != NULL) navigate(to);
		else eval(line, NULL);
		free(base);
	}

	bestlineHistoryFree();
}


/*============================================================================*/
void load_config_file(const char *filename) {
	long length;
	FILE *fp = NULL;
	char *data = NULL;

	if ((fp = fopen(filename, "rb")) == NULL) goto fail;
	if (fseek(fp, 0, SEEK_END)) goto fail;
	if ((length = ftell(fp)) <= 0) goto fail;
	if (fseek(fp, 0, SEEK_SET)) goto fail;
	if ((data = malloc(length + 1)) == NULL) goto fail;
	if (fread(data, 1, length, fp) != (size_t)length) goto fail;
	fclose(fp);
	data[length] = '\0';

	eval(data, filename);
	free(data);
	return;

fail:
	if (data) free(data);
	if (fp) fclose(fp);
}


void load_config_files() {
	char buffer[1024], *home;

	load_config_file("/etc/gplaces.conf");
	load_config_file("/usr/local/etc/gplaces.conf");
	if ((home = getenv("HOME")) != NULL) {
		snprintf(buffer, sizeof(buffer), "%s/.gplaces.conf", home);
		load_config_file(buffer);
	}
	load_config_file("gplaces.conf");
}


void parse_arguments(int argc, char **argv) {
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


void quit_client() {
	free_variable(variables);
	free_variable(aliases);
	free_variable(typehandlers);
	free_selector(bookmarks);
	free_selector(history);
	free_selector(menu);
	puts("\33[0m");
}


static void sigint(int sig) {
	(void)sig;
	fputs("^C", stderr);
}


int main(int argc, char **argv) {
	atexit(quit_client);
	signal(SIGINT, sigint);

	SSL_library_init();
	SSL_load_error_strings();

	load_config_files();
	parse_arguments(argc, argv);

	puts(
		"gplaces - 0.16.0  Copyright (C) 2022  Dima Krasner\n" \
		"based on delve 0.15.4  Copyright (C) 2019  Sebastian Steinhauer\n" \
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
