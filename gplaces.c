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
#include <limits.h>
#include <wchar.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <regex.h>
#include "queue.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <curl/curl.h>

#ifdef GPLACES_USE_LIBMAGIC
	#include <magic.h>
#endif

#ifdef GPLACES_USE_FRIBIDI
	#include <fribidi.h>
#endif

#include "bestline/bestline.h"

/*============================================================================*/
typedef struct Selector {
	SIMPLEQ_ENTRY(Selector) next;
	int index;
	char type, *raw, *repr, *scheme, *host, *port, *path, *url, *rawurl;
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
static SelectorList subscriptions = SIMPLEQ_HEAD_INITIALIZER(subscriptions);
static SelectorList menu = SIMPLEQ_HEAD_INITIALIZER(menu);
static char prompt[256] = "\33[35m>\33[0m ";
static int interactive;


/*============================================================================*/
__attribute__((format(printf, 2, 3)))
static void error(int fatal, const char *fmt, ...) {
	va_list va;
	if (interactive) fwrite("\33[31m\n", 1, 6, stderr);
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	if (interactive) fwrite("\33[0m\n", 1, 5, stderr);
	else fputc('\n', stderr);
	if (fatal) exit(EXIT_FAILURE);
}


/*============================================================================*/
static char *str_copy(const char *str) {
	char *new;
	if ((new = strdup(str)) == NULL) error(1, "cannot allocate new string");
	return new;
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


static char *set_var(VariableList *list, const char *name, const char *value) {
	Variable *var;

	if (name == NULL) return NULL;
	LIST_FOREACH(var, list, next) {
		if (!strcasecmp(var->name, name)) break;
	}

	if (value) {
		if (var == NULL) {
			if ((var = malloc(sizeof(Variable))) == NULL) error(1, "cannot allocate new variable");
			var->name = str_copy((char*)name);
			var->data = str_copy(value);
			LIST_INSERT_HEAD(list, var, next);
		} else {
			free(var->data);
			var->data = str_copy(value);
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
	if (new == NULL) error(1, "cannot allocate new selector");
	new->type = type;
	new->raw = str_copy(raw);
	new->repr = new->raw;
	return new;
}


static void free_selector(Selector *sel) {
	free(sel->raw);
	if (sel->repr != sel->raw) free(sel->repr);
	curl_free(sel->scheme);
	curl_free(sel->host);
	curl_free(sel->port);
	curl_free(sel->path);
	curl_free(sel->url);
	free(sel->rawurl);
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

	free(sel->rawurl);
	sel->rawurl = str_copy(url);

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


static Selector *find_selector(SelectorList *list, int index) {
	Selector *sel;
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
	static char buffer[LINE_MAX];
	char *line, *url;
	SelectorList list = SIMPLEQ_HEAD_INITIALIZER(list);
	Selector *sel;
	int pre = 0, i, index = 1;

	for (i = 0; i < 512 && (line = fgets(buffer, sizeof(buffer), fp)) != NULL; ++i) {
		if (strncmp(line, "```", 3) == 0) {
			pre = !pre;
			continue;
		}

		line[strcspn(line, "\r\n")] = '\0';

		if (pre)
			sel = new_selector('`', line);
		else if (line[0] == '=' && line[1] == '>') {
			sel = new_selector('l', line);
			url = line + 2 + strspn(line + 2, " \t");
			line = url + strcspn(url, " \t");
			if (*line != '\0') {
				*line = '\0';
				line += 1 + strspn(line + 1, " \t");
			}
			if (!parse_url(from, sel, url)) { free_selector(sel); continue; }
			if (*line) sel->repr = str_copy(line);
			else sel->repr = str_copy(url);
			sel->index = index++;
		} else if (*line == '#')
			sel = new_selector('#', line);
		else if (*line == '>' || (line[0] == '*' && line[1] == ' ')) {
			sel = new_selector(*line, line);
			sel->repr = str_copy(line + 1 + strspn(line + 1, " \t"));
		} else sel = new_selector('i', line);

		SIMPLEQ_INSERT_TAIL(&list, sel, next);
	}

	if (i == 512) error(0, "gemtext is truncated to 512 lines");

	return list;
}


/*============================================================================*/
static char *next_token(char **str) {
	char *begin;
	if (*str == NULL) return NULL;
	*str += strspn(*str, " \v\t");
	switch (**str) {
		case '\0': case '#': return NULL;
		case '"': ++*str; return strtok_r(*str, "\"", str);
		default:
			begin = *str;
			*str += strcspn(*str, " \v\t");
			if (**str != '\0') { **str = '\0'; ++*str; }
			return begin;
	}
}


static int get_terminal_width() {
	struct winsize wz;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &wz);
	return wz.ws_col > 20 ? wz.ws_col : 20;
}


/*============================================================================*/
static const char *find_mime_handler(const char *mime) {
	const char *handler = set_var(&variables, mime, NULL);
	if (!handler) fprintf(stderr, "no handler for `%s`\n", mime);
	return handler;
}


static void reap(const char *command, pid_t pid) {
	pid_t ret;
	int status;

	while ((ret = waitpid(pid, &status, 0)) < 0 && errno == EINTR);
	if (ret == pid && WIFEXITED(status)) fprintf(stderr, "`%s` has exited with exit status %d\n", command, WEXITSTATUS(status));
	else if (ret == pid && !WIFEXITED(status)) fprintf(stderr, "`%s` has exited abnormally\n", command);
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
	else error(0, "could not execute `%s`", command);
}


/*============================================================================*/
static int tofu(X509 *cert, const char *host) {
	static char hosts[1024], buffer[1024 + 1 + EVP_MAX_MD_SIZE * 2 + 2], hex[EVP_MAX_MD_SIZE * 2 + 1];
	static unsigned char md[EVP_MAX_MD_SIZE];
	size_t hlen;
	const char *home, *line;
	FILE *fp;
	unsigned int mdlen, i;
	int trust = 1;

	if (X509_digest(cert, EVP_sha512(), md, &mdlen) == 0) return 0;

	for (i = 0; i < mdlen; ++i) {
		hex[i * 2] = "0123456789ABCDEF"[md[i] >> 4];
		hex[i * 2 + 1] = "0123456789ABCDEF"[md[i] & 0xf];
	}
	hex[mdlen * 2] = '\0';

	hlen = strlen(host);

	if ((home = getenv("XDG_DATA_HOME")) != NULL) snprintf(hosts, sizeof(hosts), "%s/gplaces_hosts", home);
	else if ((home = getenv("HOME")) != NULL) snprintf(hosts, sizeof(hosts), "%s/.gplaces_hosts", home);
	else return 0;

	if ((fp = fopen(hosts, "r")) != NULL) {
		while ((line = fgets(buffer, sizeof(buffer), fp)) != NULL) {
			if (strncmp(line, host, hlen)) continue;
			if (line[hlen] != ' ') continue;
			trust = strncmp(&line[hlen + 1], hex, mdlen * 2) == 0 && line[hlen + 1 + mdlen * 2] == '\n';
			goto out;
		}

		fclose(fp); fp = NULL;
	}

	if (trust) trust = (fp = fopen(hosts, "a")) != NULL && fprintf(fp, "%s %s\n", host, hex) > 0;

out:
	if (fp) fclose(fp);
	return trust;
}


static void mkcert(const char *crtpath, const char *keypath) {
	EVP_PKEY *key = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *eckey = NULL;
#endif
	X509 *cert = NULL;
	X509_NAME *name;
	const char *curve, *digest, *cn;
	const EVP_MD *md;
	FILE *crtf = NULL, *keyf = NULL;
	long days;
	int ok = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	int assigned = 0, nid;
#endif

	if ((days = get_var_integer("DAYS", 1825)) <= 0) days = 1825;
	if ((curve = set_var(&variables, "CURVE", NULL)) == NULL || *curve == '\0') curve = SN_X9_62_prime256v1;
	if ((digest = set_var(&variables, "DIGEST", NULL)) == NULL || *digest == '\0') digest = LN_sha256;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	ok = ((((cn = set_var(&variables, "CN", NULL)) != NULL && *cn != '\0') || ((cn = getenv("USER")) != NULL && *cn != '\0')) && (md = EVP_get_digestbyname(digest)) != NULL && (cert = X509_new()) != NULL && X509_set_version(cert, 2) == 1 && X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL && X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * days) != NULL && (name = X509_get_subject_name(cert)) != NULL && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) == 1 && (key = EVP_PKEY_new()) != NULL && (nid = OBJ_sn2nid(curve)) != NID_undef && (eckey = EC_KEY_new_by_curve_name(nid)) != NULL && EC_KEY_generate_key(eckey) == 1 && (assigned = EVP_PKEY_assign_EC_KEY(key, eckey)) == 1 && X509_set_pubkey(cert, key) == 1 && X509_sign(cert, key, md) != 0 && (crtf = fopen(crtpath, "w")) != NULL && (keyf = fopen(keypath, "w")) != NULL && PEM_write_X509(crtf, cert) != 0 && PEM_write_PrivateKey(keyf, key, NULL, NULL, 0, NULL, NULL) != 0);
#else
	ok = ((((cn = set_var(&variables, "CN", NULL)) != NULL && *cn != '\0') || ((cn = getenv("USER")) != NULL && *cn != '\0')) && (md = EVP_get_digestbyname(digest)) != NULL && (cert = X509_new()) != NULL && X509_set_version(cert, X509_VERSION_3) == 1 && X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL && X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * days) != NULL && (name = X509_get_subject_name(cert)) != NULL && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) == 1 && (key = EVP_EC_gen(curve)) != NULL && X509_set_pubkey(cert, key) == 1 && X509_sign(cert, key, md) != 0 && (crtf = fopen(crtpath, "w")) != NULL && (keyf = fopen(keypath, "w")) != NULL && PEM_write_X509(crtf, cert) != 0 && PEM_write_PrivateKey(keyf, key, NULL, NULL, 0, NULL, NULL) != 0);
#endif

	if (keyf) {
		fclose(keyf);
		if (ok == 0) unlink(keypath);
	}
	if (crtf) {
		fclose(crtf);
		if (ok == 0) unlink(crtpath);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (!assigned && eckey) EC_KEY_free(eckey);
#endif
	if (key) EVP_PKEY_free(key);
	if (cert) X509_free(cert);
}


static int do_download(Selector *sel, SSL_CTX *ctx, const char *crtpath, const char *keypath, FILE *fp, char **mime, int ask) {
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP}, *result, *it;
	static char buffer[1024];
	struct stat stbuf;
	char *data = NULL, *crlf, *meta, *line, *url;
	struct timeval tv = {0};
	size_t total, prog = 0, cap = 2 + 1 + 1024 + 2 + 2048 + 1; /* 99 meta\r\n\body0 */
	int timeout, fd = -1, len, received, ret = 40, err = 0;
	BIO *bio = NULL;
	SSL *ssl = NULL;
	X509 *cert = NULL;

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;
	tv.tv_sec = timeout;

	if ((err = getaddrinfo(sel->host, sel->port, &hints, &result)) != 0) {
		error(0, "cannot resolve hostname `%s`: %s", sel->host, gai_strerror(err));
		goto fail;
	}

	for (it = result; it && err != EINTR; it = it->ai_next) {
		if ((fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol)) == -1) { err = errno; continue; }
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0 && connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
		err = errno;
		close(fd); fd = -1;
	}

	freeaddrinfo(result);

	if (fd == -1) {
		error(0, "cannot connect to `%s`:`%s`: %s", sel->host, sel->port, strerror(err));
		goto fail;
	}

	if ((ssl = SSL_new(ctx)) == NULL || (bio = BIO_new_socket(fd, BIO_NOCLOSE)) == NULL || SSL_set_tlsext_host_name(ssl, sel->host) == 0) {
		error(0, "cannot establish secure connection to `%s`:`%s`", sel->host, sel->port);
		goto fail;
	}
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);

	if ((err = SSL_get_error(ssl, SSL_do_handshake(ssl))) != SSL_ERROR_NONE) {
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "cannot establish secure connection to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot establish secure connection to `%s`:`%s`: error %d", sel->host, sel->port, err);
		goto fail;
	}

	if ((cert = SSL_get_peer_certificate(ssl)) == NULL) {
		error(0, "cannot establish secure connection to `%s`:`%s`: no peer certificate", sel->host, sel->port);
		goto fail;
	}

	if (!tofu(cert, sel->host)) {
		error(0, "cannot establish secure connection to `%s`:`%s`: bad certificate", sel->host, sel->port);
		goto fail;
	}

	len = snprintf(buffer, sizeof(buffer), "%s\r\n", sel->url);
	if ((err = SSL_get_error(ssl, SSL_write(ssl, buffer, len >= (int)sizeof(buffer) ? (int)sizeof(buffer) - 1 : len))) != SSL_ERROR_NONE) {
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "cannot send request to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot send request to `%s`:`%s`: error %d", sel->host, sel->port, err);
		goto fail;
	}

	if ((data = malloc(cap)) == NULL) error(1, "cannot allocate download data");

	for (total = 0; total < cap - 1 && (total < 4 || (data[total - 2] != '\r' && data[total - 1] != '\n')); ++total) {
		if ((received = SSL_read(ssl, &data[total], 1)) > 0) continue;
		if (received == 0) break;
		if ((err = SSL_get_error(ssl, received)) == SSL_ERROR_ZERO_RETURN) break;
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "failed to download `%s`: cancelled", sel->url);
		else error(0, "failed to download `%s`: error %d", sel->url, err);
		goto fail;
	}
	if (total < 4 || data[0] < '1' || data[0] > '6' || data[1] < '0' || data[1] > '9' || (total > 4 && data[2] != ' ') || data[total - 2] != '\r' || data[total - 1] != '\n') goto fail;
	data[total] = '\0';

	crlf = &data[total - 2];
	*crlf = '\0';
	meta = &data[3];
	if (meta >= crlf) meta = "";

	switch (data[0]) {
		case '2':
			if (!*meta) goto fail;

			while ((received = SSL_read(ssl, crlf + 1, cap - (crlf - data) - 1)) > 0) {
				if (fwrite(crlf + 1, 1, received, fp) != (size_t)received) goto fail;
				total += received;
				if ((total > 2048 && total - prog > total / 20)) { fputc('.', stderr); prog = total; }
				if (total > SIZE_MAX - cap) goto fail;
			}
			if (received < 0 && ((err = SSL_get_error(ssl, received)) != SSL_ERROR_ZERO_RETURN)) { /* some servers seem to ignore this part of the specification (v0.16.1): "As per RFCs 5246 and 8446, Gemini servers MUST send a TLS `close_notify`" */
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "failed to download `%s`: cancelled", sel->url);
				else error(0, "failed to download `%s`: error %d", sel->url, err);
				goto fail;
			}
			if (prog > 0) fputc('\n', stderr);

			*mime = str_copy(meta);
			break;

		case '1':
			if (!ask || !*meta) goto fail;
			snprintf(buffer, sizeof(buffer), "\33[35m%s>\33[0m ", meta);
			if (data[1] == '1') bestlineMaskModeEnable();
			if ((line = bestline(buffer)) == NULL) goto fail;
			if (data[1] != '1' && interactive) bestlineHistoryAdd(line);
			if (data[1] == '1') bestlineMaskModeDisable();
			if (curl_url_set(sel->cu, CURLUPART_QUERY, line, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_URL, &url, 0) != CURLUE_OK) { free(line); goto fail; }
			curl_free(sel->url); sel->url = url;
			free(line);
			break;

		case '3':
			if (!*meta || curl_url_set(sel->cu, CURLUPART_URL, meta, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_URL, &url, 0) != CURLUE_OK) goto fail;
			curl_free(sel->url); sel->url = url;
			fprintf(stderr, "redirected to `%s`\n", sel->url);
			break;

		case '6':
			if (*meta) error(0, "`%s`: %s", sel->host, meta);
			else error(0, "client certificate is required for `%s`", sel->host);
			if (ask && stat(crtpath, &stbuf) != 0 && errno == ENOENT && stat(keypath, &stbuf) != 0 && errno == ENOENT) {
				snprintf(buffer, sizeof(buffer), "\33[35mGenerate client certificate for `%s`? (y/n)>\33[0m ", sel->host);
				if ((line = bestline(buffer)) != NULL) {
					if (*line == 'y' || *line == 'Y') mkcert(crtpath, keypath);
					free(line);
				}
			}
			if (SSL_CTX_use_certificate_file(ctx, crtpath, SSL_FILETYPE_PEM) == 1 && SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) == 1) break;
			error(0, "failed to load client certificate for `%s`: %s", sel->host, ERR_reason_error_string(ERR_get_error()));
			ret = 50;
			goto fail;

		default:
			error(0, "cannot download `%s`: %s", sel->url, *meta ? meta : data);
	}

	ret = (data[0] - '0') * 10 + (data[1] - '0');

fail:
	free(data);
	if (cert) X509_free(cert);
	if (ssl) SSL_free(ssl);
	else if (bio) BIO_free(bio);
	if (fd != -1) close(fd);
	return ret;
}


static void sigint(int sig) {
	(void)sig;
}


static int download(Selector *sel, FILE *fp, char **mime, int ask) {
	static char crtpath[1024], keypath[1024], suffix[1024];
	struct stat stbuf;
	struct sigaction sa = {.sa_handler = sigint}, old;
	const char *home;
	SSL_CTX *ctx = NULL;
	int status, redirs = 0, needcert = 0, ret = 0, len, i, off;

	if ((home = getenv("XDG_DATA_HOME")) != NULL) {
		if ((off = snprintf(crtpath, sizeof(crtpath), "%s/gplaces_%s", home, sel->host)) >= (int)sizeof(crtpath)) return 0;
	} else if ((home = getenv("HOME")) == NULL || (off = snprintf(crtpath, sizeof(crtpath), "%s/.gplaces_%s", home, sel->host)) >= (int)sizeof(crtpath)) return 0;

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) return 0;
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/*
	 * If the user requests gemini://example.com/foo/bar/baz.gmi, try to load:
	 *
	 *  1) The certificate for gemini://example.com/foo/bar/baz.gmi
	 *  2) The certificate for gemini://example.com/foo/bar
	 *  3) The certificate for gemini://example.com/foo
	 *  4) The certificate for gemini://example.com
	 *
	 * If we found a certificate for one of these, stop even if loading fails.
	 */
	for (len = 0; len < (int)sizeof(suffix) - 1 && sel->path[len] != '\0'; ++len) suffix[len] = sel->path[len] == '/' ? '_' : sel->path[len];
	suffix[len] = '\0';
	memcpy(keypath, crtpath, off);
	for (i = sel->path[len - 1] == '/' ? len - 1 : len; i >= 0; --i) {
		if (i < len && sel->path[i] != '/') continue;
		snprintf(&crtpath[off], sizeof(crtpath) - off, "%.*s.crt", i, suffix);
		snprintf(&keypath[off], sizeof(keypath) - off, "%.*s.key", i, suffix);
		if (stat(crtpath, &stbuf) == 0 && stat(keypath, &stbuf) == 0) {
			SSL_CTX_use_certificate_file(ctx, crtpath, SSL_FILETYPE_PEM);
			SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM);
			goto loaded;
		}
	}

	/*
	 * if we failed to find a matching certificate and a certificate is
	 * generated, we want to associate it with the full path
	 */
	snprintf(&crtpath[off], sizeof(crtpath) - off, "%s.crt", suffix);
	snprintf(&keypath[off], sizeof(keypath) - off, "%s.key", suffix);

loaded:
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, &old);

	do {
		status = do_download(sel, ctx, crtpath, keypath, fp, mime, ask);
		if ((ret = (status >= 20 && status <= 29))) break;
	} while ((status >= 10 && status <= 19) || (status >= 60 && status <= 69 && ++needcert == 1) || (status >= 30 && status <= 39 && ++redirs < 5));

	sigaction(SIGINT, &old, NULL);

	SSL_CTX_free(ctx);

	if (redirs == 5) error(0, "too many redirects from `%s`", sel->url);
	return ret;
}


static const char *get_filename(Selector *sel, size_t *len) {
	/*
	 * skip the leading /
	 * trim all trailing /
	 * if the path is /, use the hostname
	 * find the last / and skip it
	 * if there's no /, return the path
	 */
	const char *p;
	*len = strlen(&sel->path[1]);
	while (*len > 0 && sel->path[1 + *len - 1] == '/') --*len;
	if (*len == 0) {
		*len = strlen(sel->host);
		return sel->host;
	}
	p = memrchr(&sel->path[1], '/', *len);
	if (p == NULL) return &sel->path[1];
	*len -= p + 1 - &sel->path[1];
	return p + 1;
}


static void download_to_file(Selector *sel, const char *def) {
	static char suggestion[256], buffer[1024];
	FILE *fp;
	char *mime = NULL, *input = NULL, *download_dir;
	const char *filename = def;
	size_t len;
	int ret;

	if (def == NULL) {
		def = get_filename(sel, &len);
		if (((download_dir = set_var(&variables, "DOWNLOAD_DIRECTORY", NULL)) != NULL && *download_dir != '\0') || (download_dir = getenv("XDG_DOWNLOAD_DIR")) != NULL) snprintf(suggestion, sizeof(suggestion), "%s/%.*s", download_dir, (int)len, def);
		else if ((download_dir = getenv("HOME")) != NULL) {
			snprintf(suggestion, sizeof(suggestion), "%s/Downloads", download_dir);
			if (access(suggestion, F_OK) == 0) snprintf(suggestion, sizeof(suggestion), "%s/Downloads/%.*s", download_dir, (int)len, def);
			else snprintf(suggestion, sizeof(suggestion), "%s/%.*s", download_dir, (int)len, def);
		} else snprintf(suggestion, sizeof(suggestion), "./%.*s", (int)len, def);
		snprintf(buffer, sizeof(buffer), "enter filename (press ENTER for `%s`): ", suggestion);
		if ((input = bestline(buffer)) == NULL) return;
		if (*input != '\0') filename = input;
		else filename = suggestion;
	}
	if ((fp = fopen(filename, "wb")) == NULL) error(0, "cannot create file `%s`: %s", filename, strerror(errno));
	else {
		ret = download(sel, fp, &mime, 1);
		fclose(fp);
		free(mime);
		if (!ret) unlink(filename);
	}
	free(input);
}


static SelectorList download_to_temp(Selector *sel, int ask, int gemtext) {
	static char filename[1024];
	FILE *fp = NULL;
	const char *tmpdir, *handler;
	SelectorList list = LIST_HEAD_INITIALIZER(list);
	char *mime = NULL;
	int fd;

	if ((tmpdir = getenv("TMPDIR")) == NULL) tmpdir = "/tmp/";
	snprintf(filename, sizeof(filename), "%sgplaces.XXXXXXXX", tmpdir);
	if ((fd = mkstemp(filename)) == -1 || (fp = fdopen(fd, "r+w")) == NULL) {
		error(0, "cannot create temporary file: %s", strerror(errno));
		goto out;
	}
	if (!download(sel, fp, &mime, ask) || fflush(fp) == EOF) goto out;
	if (!strncmp(mime, "text/gemini", 11)) {
		if (fseek(fp, 0, SEEK_SET) == -1) goto out;
		list = parse_gemtext(sel, fp);
	} else if (!gemtext && (handler = find_mime_handler(mime)) != NULL) execute_handler(handler, filename, sel);

out:
	free(mime);
	if (fp) fclose(fp);
	if (fd != -1) {
		if (fp == NULL) close(fd);
		unlink(filename);
	}
	return list;
}


/*============================================================================*/
static int ndigits(int n) {
	int digits = 0;
	for ( ; n > 0; n /= 10, ++digits);
	return digits;
}


static void print_gemtext(FILE *fp, SelectorList *list, const char *filter) {
#ifdef GPLACES_USE_FRIBIDI
	static char repr[LINE_MAX];
	static wchar_t wline[LINE_MAX], vis[LINE_MAX];
	FriBidiParType type = FRIBIDI_TYPE_ON;
#endif
	mbstate_t ps;
	regex_t re;
	size_t size, wlen;
	Selector *sel;
	const char *p;
	const wchar_t *wp;
	int width, w, wwidth, wchars, out, extra, wi;

	if (filter && regcomp(&re, filter, REG_NOSUB) != 0) filter = NULL;
	width = get_terminal_width();

	SIMPLEQ_FOREACH(sel, list, next) {
		if (filter && regexec(&re, sel->raw, 0, NULL, 0) != 0) continue;
		//if (!interactive) { fprintf(fp, "%s\n", sel->raw); continue; }
		size = strlen(sel->repr);
		if (size == 0) { fputc('\n', fp); continue; }

		memset(&ps, 0, sizeof(ps));
		p = sel->repr;
		wlen = mbsrtowcs(wline, &p, LINE_MAX, &ps);

		for (wi = 0, wp = vis; wi < (int)wlen; wi += wchars, wi += wcsspn(&wline[wi], L" "), wp = vis) {
			extra = 0;
			switch (sel->type) {
				case 'l': if (wi == 0) extra = 3 + ndigits(sel->index); break;
				case '>':
				case '*': extra = 2; break;
			}

			memset(&ps, 0, sizeof(ps));
			for (wchars = 0, wwidth = 0; wi + wwidth < (int)wlen && wwidth < width - extra; ++wchars) {
				if ((w = wcwidth(wline[wi + wchars])) < 0) w = 1;
				else if (wwidth + w > width - extra) break;
				wwidth += w;
			}

#ifdef GPLACES_USE_FRIBIDIx
			fribidi_log2vis((FriBidiChar *)&wline[wi], wchars, &type, (FriBidiChar *)vis, NULL, NULL, NULL);
			vis[wchars] = L'\0';
#endif

			memset(&ps, 0, sizeof(ps));
			out = wcsnrtombs(repr, &wp, wchars, LINE_MAX, &ps);

			switch (sel->type) {
				case 'l':
					if (wi == 0) {
						fprintf(fp, "\33[4;36m[%d]\33[0;39m %.*s\n", sel->index, out, repr);
						break;
					}
					/* fall through */
				case 'i': fprintf(fp, "%.*s\n", out, repr); break;
				case '#': fprintf(fp, "\33[4m%.*s\33[0m\n", out, repr); break;
				case '`':
					wchars = wlen;
					fprintf(fp, "%s\n", sel->repr);
					break;
				case '>':
					fprintf(fp, "%c %.*s\n", sel->type, out, repr);
					break;
				default:
					if (wi == 0) fprintf(fp, "%c %.*s\n", sel->type, out, repr);
					else fprintf(fp, "  %.*s\n", out, repr);
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

	if ((fp = fdopen(fds[1], "w")) == NULL) close(fds[1]);
	else {
		print_gemtext(fp, list, NULL);
		fclose(fp);
	}

	reap(pager, pid);
}


static void show_gemtext(SelectorList *list, const char *filter, int page) {
	if (page && !filter && interactive) page_gemtext(list);
	print_gemtext(stdout, list, filter);
}


static void navigate(Selector *to) {
	const char *handler = NULL, *ext;
	SelectorList new = SIMPLEQ_HEAD_INITIALIZER(new);
	FILE *fp;
#ifdef GPLACES_USE_LIBMAGIC
	magic_t mag;
#endif
	const char *mime = NULL;

	if (!strcmp(to->scheme, "file")) {
		if ((ext = strrchr(to->path, '.')) != NULL && !strcmp(ext, ".gmi")) {
			if ((fp = fopen(to->path, "r")) == NULL) return;
			new = parse_gemtext(to, fp);
			fclose(fp);
		} else {
#ifdef GPLACES_USE_LIBMAGIC
			if ((mag = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS | MAGIC_ERROR)) == NULL) return;
			if (magic_load(mag, NULL) == 0) mime = magic_file(mag, to->path);
			if (mime) handler = find_mime_handler(mime);
			magic_close(mag);
#endif
			if (mime == NULL) error(0, "unable to detect the MIME type of %s", to->path);
			goto handle;
		}
	} else if (strcmp(to->scheme, "gemini")) {
		handler = find_mime_handler(to->scheme);
		goto handle;
	} else new = download_to_temp(to, interactive, 0);

	if (SIMPLEQ_EMPTY(&new)) return;
	snprintf(prompt, sizeof(prompt), "\33[35m%s>\33[0m ", to->url + 9);
	free_selectors(&menu);
	menu = new;
	show_gemtext(&new, NULL, 1);
	return;

handle:
	if (handler) execute_handler(handler, to->url, to);
}


/*============================================================================*/
static const Help gemini_help[] = {
	{
		"authors",
		"Dima Krasner <dima@dimakrasner.com>\n" \
		"Sebastian Steinhauer <s.steinhauer@yahoo.de>" \
	},
	{
		"commands",
		"help          save          set           show          sub" \
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
		"save",
		"SAVE <item-id|url> [<path>]" \
	},
	{
		"set",
		"SET <name> <value>" \
	},
	{
		"show",
		"SHOW [<filter>]" \
	},
	{
		"sub",
		"SUB [<url>]" \
	},
	{ NULL, NULL }
};


/*============================================================================*/
static void cmd_show(char *line) {
	show_gemtext(&menu, next_token(&line), 1);
}


static void cmd_save(char *line) {
	char *id, *path;
	Selector *to;
	int index;
	id = next_token(&line);
	path = next_token(&line);
	if ((index = atoi(id)) > 0 && (to = find_selector(&menu, index)) != NULL) download_to_file(to, path);
	else if (index <= 0) {
		to = new_selector('l', line);
		if (parse_url(NULL, to, id)) download_to_file(to, path);
		free_selector(to);
	}
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


static void cmd_sub(char *line) {
	char ts[11];
	SelectorList list, feed = SIMPLEQ_HEAD_INITIALIZER(feed);
	Selector *sel, *it, *copy;
	struct tm *tm;
	time_t t;
	int index = 1;
	char *url = next_token(&line);
	if (url) {
		Selector *sel = new_selector('l', url);
		if (parse_url(NULL, sel, url)) SIMPLEQ_INSERT_TAIL(&subscriptions, sel, next);
		else free_selector(sel);
	} else {
		t = time(NULL);
		tm = gmtime(&t);
		strftime(ts, sizeof(ts), "%Y-%m-%d", tm);

		SIMPLEQ_FOREACH(sel, &subscriptions, next) {
			list = download_to_temp(sel, 0, 1);
			if (SIMPLEQ_EMPTY(&list)) continue;

			copy = new_selector('l', sel->raw);
			if (!parse_url(NULL, copy, sel->url)) { free_selector(copy); free_selectors(&list); continue; }
			copy->index = index++;

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == '#' && (it->raw[1] == ' ' || it->raw[1] == '\t')) {
					copy->repr = str_copy(&it->repr[2]);
					break;
				}
			}

			SIMPLEQ_INSERT_TAIL(&feed, copy, next);

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == 'l' && !strncmp(it->repr, ts, 10)) {
					copy = new_selector('l', it->raw);
					if (!parse_url(NULL, copy, it->url)) { free_selector(copy); continue; }
					copy->repr = str_copy(it->repr);
					copy->index = index++;
					SIMPLEQ_INSERT_TAIL(&feed, copy, next);
				}
			}

			free_selectors(&list);
		}
		if (SIMPLEQ_EMPTY(&feed)) return;
		free_selectors(&menu);
		menu = feed;
		show_gemtext(&feed, NULL, 0);
	}
}


static void cmd_set(char *line) {
	char *name = next_token(&line);
	char *data = next_token(&line);

	if (name != NULL && data != NULL) set_var(&variables, name, data);
}


static const Command gemini_commands[] = {
	{ "show", cmd_show },
	{ "save", cmd_save },
	{ "help", cmd_help },
	{ "sub", cmd_sub },
	{ "set", cmd_set },
	{ NULL, NULL }
};


/*============================================================================*/
static void eval(const char *input, const char *filename, int line_no) {
	const Command *cmd;
	Selector *to;
	char *copy, *line, *token, *var, *url;

	copy = line = str_copy(input); /* copy input as it will be modified */

	if ((token = url = next_token(&line)) != NULL && *token != '\0') {
		for (cmd = gemini_commands; cmd->name; ++cmd) {
			if (!strcasecmp(cmd->name, token)) {
				cmd->func(line);
				free(copy);
				return;
			}
		}
		if ((var = set_var(&variables, token, NULL)) != NULL) url = var;
		to = new_selector('l', token);
		if (parse_url(NULL, to, url)) navigate(to);
		else if (filename == NULL) error(0, "unknown command `%s`", token);
		else error(0, "unknown command `%s` in file `%s` at line %d", token, filename, line_no);
		free_selector(to);
	}

	free(copy);
}


static void shell_name_completion(const char *text, bestlineCompletions *lc) {
	static int len;
	const Command *cmd;
	const Variable *var;

	len = strlen(text);

	for (cmd = gemini_commands; cmd->name; ++cmd)
		if (!strncasecmp(cmd->name, text, len)) bestlineAddCompletion(lc, cmd->name);

	LIST_FOREACH(var, &variables, next)
		if (!strncasecmp(var->name, text, len)) bestlineAddCompletion(lc, var->name);
}


static char *shell_hints(const char *buf, const char **ansi1, const char **ansi2) {
	static char hint[1024];
	Selector *sel;
	const char *val;
	int first = -1, last = -1, index;
	(void)ansi1;
	(void)ansi2;
	if (strcspn(buf, " ") == 0) {
		SIMPLEQ_FOREACH(sel, &menu, next) {
			if (sel->type != 'l') continue;
			if (first == -1) first = sel->index;
			last = sel->index;
		}
		if (first != last) {
			snprintf(hint, sizeof(hint), "%d-%d, URL, variable or command", first, last);
			return hint;
		} else if (first != -1) return "1, URL, variable or command";
		else return "URL, variable or command; type `help` for help";
	}
	if ((index = atoi(buf)) > 0) {
		if ((sel = find_selector(&menu, index)) == NULL) return NULL;
		if (strncmp(sel->rawurl, "gemini://", 9) == 0) snprintf(hint, sizeof(hint), " %s", &sel->rawurl[9]);
		else snprintf(hint, sizeof(hint), " %s", sel->rawurl);
	} else if ((val = set_var(&variables, buf, NULL)) != NULL) {
		if (strncmp(val, "gemini://", 9) == 0) snprintf(hint, sizeof(hint), " %s", &val[9]);
		else snprintf(hint, sizeof(hint), " %s", val);
	} else return NULL;
	return hint;
}


static void shell(int argc, char **argv) {
	static char path[1024];
	const char *home = NULL;
	char *line, *base;
	Selector *to = NULL;
	int index;

	if (interactive) {
		bestlineSetCompletionCallback(shell_name_completion);
		if ((home = getenv("XDG_DATA_HOME")) != NULL) {
			snprintf(path, sizeof(path), "%s/gplaces_history", home);
			bestlineHistoryLoad(path);
		} else if ((home = getenv("HOME")) != NULL) {
			snprintf(path, sizeof(path), "%s/.gplaces_history", home);
			bestlineHistoryLoad(path);
		}
	}

	if (optind < argc) eval(argv[optind], NULL, 0);

	for (;;) {
		bestlineSetHintsCallback(shell_hints);
		if ((line = base = bestline(prompt)) == NULL) break;
		bestlineSetHintsCallback(NULL);
		if ((index = atoi(line)) > 0 && (to = find_selector(&menu, index)) != NULL) {
			if (to->url && interactive) bestlineHistoryAdd(to->url);
			else if (interactive) bestlineHistoryAdd(line);
			navigate(to);
		} else if (index <= 0) {
			eval(line, NULL, 0);
			if (interactive) bestlineHistoryAdd(line);
		}
		free(base);
	}

	if (interactive && home != NULL) bestlineHistorySave(path);
}


/*============================================================================*/
static int load_rc_file(const char *filename) {
	static char buffer[1024];
	char *line;
	FILE *fp;
	int line_no = 0, ret;

	if ((fp = fopen(filename, "rb")) == NULL) return 0;
	while ((line = fgets(buffer, sizeof(buffer), fp)) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';
		eval(buffer, filename, ++line_no);
	}

	ret = feof(fp);

	fclose(fp);
	return ret;
}


static void load_rc_files(const char *rcfile) {
	static char buffer[1024];
	const char *home;

	if (rcfile) { load_rc_file(rcfile); return; }
	if ((home = getenv("XDG_CONFIG_HOME")) != NULL) {
		snprintf(buffer, sizeof(buffer), "%s/gplacesrc", home);
		if (load_rc_file(buffer)) return;
	}
	if ((home = getenv("HOME")) != NULL) {
		snprintf(buffer, sizeof(buffer), "%s/.gplacesrc", home);
		if (load_rc_file(buffer)) return;
	}
	load_rc_file(CONFDIR"/gplacesrc");
}


static const char *parse_arguments(int argc, char **argv) {
	const char *rcfile = NULL;
	int ch;
	while ((ch = getopt(argc, argv, "r:")) != -1) {
		switch (ch) {
			case 'r':
				rcfile = optarg;
				break;

			default:
				fprintf(stderr,
					"usage: gplaces [-r rc-file] [url]\n"
				);
				exit(EXIT_SUCCESS);
		}
	}
	return rcfile;
}


static void quit_client() {
	free_variables(&variables);
	free_selectors(&subscriptions);
	free_selectors(&menu);
	if (interactive) puts("\33[0m");
}


int main(int argc, char **argv) {
	setlocale(LC_ALL, "");
	atexit(quit_client);
	setlinebuf(stdout); /* if stdout is a file, flush after every line */

	SSL_library_init();
	SSL_load_error_strings();

	interactive = isatty(STDOUT_FILENO);

	load_rc_files(parse_arguments(argc, argv));

	if (interactive) puts(
		"gplaces - "GPLACES_VERSION"  Copyright (C) 2022  Dima Krasner\n" \
		"Based on delve 0.15.4  Copyright (C) 2019  Sebastian Steinhauer\n" \
		"This program comes with ABSOLUTELY NO WARRANTY; for details type `help license'.\n" \
		"This is free software, and you are welcome to redistribute it\n" \
		"under certain conditions; type `help license' for details.\n"
	);

	shell(argc, argv);

	return 0;
}
/* vim: set ts=4 sw=4 noexpandtab: */
