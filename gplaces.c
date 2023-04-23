/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2022, 2023  Dima Krasner
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
#include <sys/mman.h>
#include "queue.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <curl/curl.h>

#ifdef GPLACES_USE_LIBIDN2
	#include <idn2.h>
#elif defined(GPLACES_USE_LIBIDN)
	#include <idna.h>
#endif

#ifdef GPLACES_USE_LIBMAGIC
	#include <magic.h>
#endif

#include "bestline/bestline.h"

/*============================================================================*/
typedef struct Selector Selector;
typedef SIMPLEQ_HEAD(, Selector) SelectorList;
typedef void (*Parser)(char *, int *pre, Selector **, SelectorList *);

typedef struct Protocol {
	const char *scheme, *port;
	int (*read)(void *, void *, int);
	int (*error)(Selector *, void *, int);
	void (*close)(void *);
	void *(*download)(Selector *, char **mime, Parser *, int ask);
} Protocol;

struct Selector {
	SIMPLEQ_ENTRY(Selector) next;
	int level;
#if defined(GPLACES_WITH_GOPHER) || defined(GPLACES_WITH_SPARTAN)
	char prompt;
#endif
	char type, *repr, *scheme, *host, *port, *path, *url, *rawurl;
	CURLU *cu;
	const Protocol *proto;
};

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
const Protocol gemini;
#ifdef GPLACES_WITH_GOPHERS
const Protocol gophers;
#endif
#ifdef GPLACES_WITH_GOPHER
const Protocol gopher;
#endif
#ifdef GPLACES_WITH_SPARTAN
const Protocol spartan;
#endif
#ifdef GPLACES_WITH_FINGER
const Protocol finger;
#endif


/*============================================================================*/
static VariableList variables = LIST_HEAD_INITIALIZER(variables);
static SelectorList subscriptions = SIMPLEQ_HEAD_INITIALIZER(subscriptions);
static SelectorList menu = SIMPLEQ_HEAD_INITIALIZER(menu);
static char prompt[256] = "\33[35m>\33[0m ";
static char *current;
static int interactive;
static int color;


/*============================================================================*/
__attribute__((format(printf, 2, 3)))
static void error(int fatal, const char *fmt, ...) {
	va_list va;
	if (color) fwrite("\33[31m\n", 1, 6, stderr);
	else fputc('\n', stderr);
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	if (color) fwrite("\33[0m\n", 1, 5, stderr);
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
static void *map_file(const char *name, int *fd, size_t *size) {
	static char path[1024];
	struct stat stbuf;
	const char *home;
	void *p;

	if ((home = getenv("XDG_DATA_HOME")) != NULL) snprintf(path, sizeof(path), "%s/gplaces_%s", home, name);
	else if ((home = getenv("HOME")) != NULL) snprintf(path, sizeof(path), "%s/.gplaces_%s", home, name);
	else return NULL;

	if ((*fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0600)) == -1) return NULL;
	if (fstat(*fd, &stbuf) == -1) { close(*fd); return NULL; }
	if ((*size = (size_t)stbuf.st_size) == 0) return NULL;
	if ((p = mmap(NULL, stbuf.st_size % SIZE_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0)) == MAP_FAILED) { close(*fd); return NULL; }
	return p;
}


__attribute__((format(printf, 2, 3)))
static int append_line(int fd, const char *fmt, ...) {
	va_list va;
	FILE *fp;
	int ret;
	if ((fp = fdopen(fd, "a")) == NULL) return 0;
	va_start(va, fmt);
	ret = vfprintf(fp, fmt, va) > 0;
	va_end(va);
	fclose(fp);
	return ret;
}


/*============================================================================*/
static Selector *new_selector(const char type) {
	Selector *new = calloc(1, sizeof(Selector));
	if (new == NULL) error(1, "cannot allocate new selector");
	new->type = type;
	return new;
}


static void free_selector(Selector *sel) {
	free(sel->repr);
	curl_free(sel->scheme);
	curl_free(sel->host);
	if (sel->proto != NULL && sel->port != sel->proto->port) curl_free(sel->port);
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


static int set_input(Selector *sel, const char *input) {
	char *query;
	if ((query = curl_easy_escape(NULL, input, 0)) == NULL) return 0;
	if (curl_url_set(sel->cu, CURLUPART_QUERY, query, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) { curl_free(query); return 0; }
	curl_free(query);
	return 1;
}


static int parse_url(Selector *sel, const char *from, const char *input) {
	static char buffer[1024];
#if defined(GPLACES_USE_LIBIDN2) || defined(GPLACES_USE_LIBIDN)
	char *host;
#endif
	int file;

	if ((sel->cu == NULL && (sel->cu = curl_url()) == NULL) || (from != NULL && curl_url_set(sel->cu, CURLUPART_URL, from, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK)) return 0;

	/* TODO: why does curl_url_set() return CURLE_OUT_OF_MEMORY if the scheme is missing, but only inside the Flatpak sandbox? */
	if (curl_url_set(sel->cu, CURLUPART_URL, sel->rawurl, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) {
		snprintf(buffer, sizeof(buffer), "gemini://%s", sel->rawurl);
		if (curl_url_set(sel->cu, CURLUPART_URL, buffer, CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) return 0;
	}

	if (input != NULL && input[0] != '\0' && !set_input(sel, input)) return 0;

	if (curl_url_get(sel->cu, CURLUPART_SCHEME, &sel->scheme, 0) != CURLUE_OK || (!(file = (strcmp(sel->scheme, "file") == 0)) && curl_url_get(sel->cu, CURLUPART_HOST, &sel->host, 0) != CURLUE_OK)) return 0;

#if defined(GPLACES_USE_LIBIDN2) || defined(GPLACES_USE_LIBIDN)
	#ifdef GPLACES_USE_LIBIDN2
	if (!file && (idn2_to_ascii_8z(sel->host, &host, IDN2_NONTRANSITIONAL) == IDN2_OK || idn2_to_ascii_8z(sel->host, &host, IDN2_TRANSITIONAL) == IDN2_OK)) {
	#elif defined(GPLACES_USE_LIBIDN)
	if (!file && idna_to_ascii_8z(sel->host, &host, 0) == IDNA_SUCCESS) {
	#endif
		if (curl_url_set(sel->cu, CURLUPART_HOST, host, 0) != CURLUE_OK) { free(host); return 0; }
		free(host);
		curl_free(sel->host); sel->host = NULL;
		if (curl_url_get(sel->cu, CURLUPART_HOST, &sel->host, 0) != CURLUE_OK) return 0;
	}
#endif

	if (curl_url_get(sel->cu, CURLUPART_URL, &sel->url, 0) != CURLUE_OK || curl_url_get(sel->cu, CURLUPART_PATH, &sel->path, 0) != CURLUE_OK) return 0;

	if (file) return 1;

	if (strcmp(sel->scheme, "gemini") == 0) {
		sel->proto = &gemini;
#ifdef GPLACES_WITH_GOPHER
	} else if (strcmp(sel->scheme, "gopher") == 0) {
		sel->proto = &gopher;
#endif
#ifdef GPLACES_WITH_GOPHERS
	} else if (strcmp(sel->scheme, "gophers") == 0) {
		sel->proto = &gophers;
#endif
#ifdef GPLACES_WITH_SPARTAN
	} else if (strcmp(sel->scheme, "spartan") == 0) {
		sel->proto = &spartan;
#endif
#ifdef GPLACES_WITH_FINGER
	} else if (strcmp(sel->scheme, "finger") == 0) {
		sel->proto = &finger;
#endif
	}

	switch (curl_url_get(sel->cu, CURLUPART_PORT, &sel->port, 0)) {
		case CURLUE_OK: break;
		case CURLUE_NO_PORT:
			if (sel->proto != NULL) sel->port = str_copy(sel->proto->port);
			break;
			/* fall through */
		default: return 0;
	}

	return 1;
}


static int redirect(Selector *sel, const char *to, size_t len) {
	char *from = sel->url; sel->url = NULL;
	curl_free(sel->scheme); sel->scheme = NULL;
	curl_free(sel->host); sel->host = NULL;
	if (sel->port != sel->proto->port) { curl_free(sel->port); }; sel->port = NULL;
	curl_free(sel->path); sel->path = NULL;
	curl_url_cleanup(sel->cu); sel->cu = NULL;
	free(sel->rawurl); if ((sel->rawurl = len > 0 ? strndup(to, len) : strdup(to)) == NULL) error(1, "cannot allocate new string");
	if (!parse_url(sel, from, NULL)) { curl_free(from); return 0; }
	curl_free(from);
	fprintf(stderr, "redirected to `%s`\n", sel->url);
	return 1;
}


static int perm_redirect(Selector *sel, const char *to) {
	size_t size = 1, len;
	const char *p, *start, *end;
	int fd, ret = 20, found = 0;

	len = strlen(sel->url);

	if ((p = map_file("redirs", &fd, &size)) == NULL && size > 0) return 40;
	else if (p != NULL) {
		for (end = p; !found && (start = memmem(end, size - (end - p), sel->url, len)) != NULL; end = start + len + 1) {
			if (!(found = ((start == p || *(start - 1) == '\n') && size - (start - p) >= len + 2 && start[len] == ' ' && start[len + 1] != '\n'))) continue;
			ret = redirect(sel, &start[len + 1], strcspn(&start[len + 1], " \n")) ? 31 : 40;
		}
		munmap((void *)p, size);
	}
	if (to != NULL && !found) ret = (append_line(fd, "%s %s\n", sel->url, to) && redirect(sel, to, -1)) ? 31 : 40;
	close(fd);
	return ret;
}


static Selector *find_selector(SelectorList *list, int index) {
	Selector *sel;
	long i = 0;
	SIMPLEQ_FOREACH(sel, list, next) if (sel->type == 'l' && ++i == index) return sel;
	return NULL;
}


static int copy_url(Selector *sel, const char *url) {
	if (url == NULL || *url == '\0') return 0;

	sel->rawurl = str_copy(url);

	return 1;
}


/*============================================================================*/
static int tcp_connect(Selector *sel) {
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP}, *result, *it;
	struct timeval tv = {0};
	int timeout, err, fd = -1;

	if ((timeout = get_var_integer("TIMEOUT", 15)) < 1) timeout = 15;
	tv.tv_sec = timeout;

	if ((err = getaddrinfo(sel->host, sel->port, &hints, &result)) != 0) {
		error(0, "cannot resolve hostname `%s`: %s", sel->host, gai_strerror(err));
		return -1;
	}

	for (it = result; it && err != EINTR; it = it->ai_next) {
		if ((fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol)) == -1) { err = errno; continue; }
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0 && connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
		err = errno;
		close(fd); fd = -1;
	}

	freeaddrinfo(result);

	if (fd == -1 && err == EINPROGRESS) error(0, "cannot connect to `%s`:`%s`: cancelled", sel->host, sel->port);
	else if (fd == -1 && err != 0) error(0, "cannot connect to `%s`:`%s`: %s", sel->host, sel->port, strerror(err));
	return fd;
}


/*============================================================================*/
static void parse_plaintext_line(char *line, int *pre, Selector **sel, SelectorList *list) {
	(void)pre;
	(void)index;

	*sel = new_selector('`');
	(*sel)->repr = str_copy(line);
	SIMPLEQ_INSERT_TAIL(list, *sel, next);
}


static void parse_gemtext_line(char *line, int *pre, Selector **sel, SelectorList *list) {
	char *url;
	int level;

	*sel = NULL;

	if (strncmp(line, "```", 3) == 0) {
		*pre = !*pre;
		return;
	}

	if (*pre) {
		*sel = new_selector('`');
		(*sel)->repr = str_copy(line);
	} else if (line[0] == '=' && line[1] == '>') {
		*sel = new_selector('l');
		url = line + 2 + strspn(line + 2, " \t");
		line = url + strcspn(url, " \t");
		if (*line != '\0') {
			*line = '\0';
			line += 1 + strspn(line + 1, " \t");
		}
		if (!copy_url(*sel, url)) { free_selector(*sel); *sel = NULL; return; }
		if (*line) (*sel)->repr = str_copy(line);
		else (*sel)->repr = str_copy(url);
	} else if (line[0] == '#' && (level = 1 + strspn(&line[1], "#")) <= 3) {
		*sel = new_selector('#');
		(*sel)->repr = str_copy(line + level + strspn(line + level, " \t"));
		(*sel)->level = level;
	} else if (*line == '>' || (line[0] == '*' && line[1] == ' ')) {
		*sel = new_selector(*line);
		(*sel)->repr = str_copy(line + 1 + strspn(line + 1, " \t"));
	} else {
		*sel = new_selector('i');
		(*sel)->repr = str_copy(line);
	}

	SIMPLEQ_INSERT_TAIL(list, *sel, next);
}


static SelectorList parse_file(FILE *fp, const Parser parser) {
	static char buffer[LINE_MAX];
	char *line;
	SelectorList list = SIMPLEQ_HEAD_INITIALIZER(list);
	size_t len;
	Selector *sel;
	int pre = 0, start = 1;

	for (sel = NULL; (line = fgets(buffer, sizeof(buffer), fp)) != NULL; sel = NULL, start = 0) {
		if ((len = strlen(line)) > 1 && buffer[len - 2] == '\r') buffer[len - 2] = '\0';
		else if (line[len - 1] == '\n') line[len - 1] = '\0';
		parser((start && strncmp(line, "\xef\xbb\xbf", 3) == 0) ? line + 3: line, &pre, &sel, &list);
	}

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
	Variable *var;
	const char *handler = NULL;
	size_t length, longest = 0;

	LIST_FOREACH(var, &variables, next) {
		if ((length = strlen(var->name)) > longest && !strncasecmp(mime, var->name, length)) {
			longest = length;
			handler = var->data;
		}
	}

	if (!handler) fprintf(stderr, "no handler for `%s`\n", mime);
	return handler;
}


static void reap(const char *command, pid_t pid, int silent) {
	pid_t ret;
	int status;

	while ((ret = waitpid(pid, &status, 0)) < 0 && errno == EINTR);
	if (!silent && ret == pid && WIFEXITED(status)) fprintf(stderr, "`%s` has exited with exit status %d\n", command, WEXITSTATUS(status));
	else if (ret == pid && !WIFEXITED(status)) fprintf(stderr, "`%s` has exited abnormally\n", command);
}


static pid_t start_handler(const char *handler, const char *filename, Selector *to, int stdin) {
	static char command[1024], buffer[sizeof("/proc/self/fd/2147483647")];
	size_t l;
	pid_t pid;

	if (stdin != -1) {
		sprintf(buffer, "/proc/self/fd/%d", stdin);
		filename = buffer;
	}

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
#ifdef GPLACES_USE_FLATPAK_SPAWN
		if (stdin == -1) execl("/usr/bin/flatpak-spawn", "flatpak-spawn", "--host", "--", "sh", "-c", command, (char *)NULL);
		else {
			sprintf(buffer, "--forward-fd=%d", stdin);
			execl("/usr/bin/flatpak-spawn", "flatpak-spawn", "--host", buffer, "--", "sh", "-c", command, (char *)NULL);
		}
#else
		execl("/bin/sh", "sh", "-c", command, (char *)NULL);
#endif
		exit(EXIT_FAILURE);
	} else if (pid < 0) error(0, "could not execute `%s`", command);
	return pid;
}


static void execute_handler(const char *handler, const char *filename, Selector *to) {
	pid_t pid;
	if ((pid = start_handler(handler, filename, to, -1)) > 0) reap(handler, pid, 0);
}


/*============================================================================*/
static int ndigits(int n) {
	int digits = 0;
	for ( ; n > 0; n /= 10, ++digits);
	return digits;
}


static void print_line(FILE *fp, Selector *sel, const regex_t *filter, int width, int *links) {
	mbstate_t ps;
	size_t size, mbs;
	wchar_t wchar;
	const char *p;
	int w, wchars, out, extra, i = 0;

	if (sel->type == 'l') ++*links;

	if (filter && regexec(filter, sel->repr, 0, NULL, 0) != 0 && (sel->rawurl == NULL || regexec(filter, sel->rawurl, 0, NULL, 0) != 0)) return;
	if (!interactive) { fprintf(fp, "%s\n", sel->repr); return; }

	size = strlen(sel->repr);

	do {
		out = (int)size;

		extra = 0;
		switch (sel->type) {
			case 'l': if (i == 0) extra = 3 + ndigits(*links); break;
			case '`': goto print;
			case '>':
			case '*': extra = 2; break;
			case '#': if (i == 0) extra = sel->level + 1;
		}

		memset(&ps, 0, sizeof(ps));
		for (wchars = 0, out = 0, p = &sel->repr[i]; out < (int)size - i && wchars < width - extra; out += mbs, p = &sel->repr[i + out], wchars += w) {
			if ((mbs = mbrtowc(&wchar, p, size - i - out, &ps)) == (size_t)-1 || mbs == (size_t)-2 || mbs == 0 || (w = wcwidth(wchar)) < 0) {
				/* best-effort, we assume 1 character == 1 byte */
				mbs = 1;
				w = 1;
			} else if (wchars + w > width - extra) break;
		}

		/* if it's a full line followed by a non-whitespace character, drop the cut word from the end */
		if (wchars + extra == width && i + out < (int)size && sel->repr[i + out] != ' ' && sel->repr[i + out] != '\t') {
			for (p = &sel->repr[i + out - 1]; p >= &sel->repr[i] && *p != ' ' && *p != '\t'; --p);
			if (p > &sel->repr[i]) out = p - &sel->repr[i];
		}

print:
		switch (sel->type) {
			case 'l':
				if (i == 0) {
					if (color) fprintf(fp, "\33[4;36m[%d]\33[0;39m %.*s\n", *links, out, &sel->repr[i]);
					else fprintf(fp, "[%d] %.*s\n", *links, out, &sel->repr[i]);
					break;
				}
				/* fall through */
			case 'i': fprintf(fp, "%.*s\n", out, &sel->repr[i]); break;
			case '#':
				if (i == 0 && color) fprintf(fp, "\33[4m%.*s %.*s\33[0m\n", sel->level, "###", out, &sel->repr[i]);
				else if (i == 0 && !color) fprintf(fp, "%.*s %.*s\n", sel->level, "###", out, &sel->repr[i]);
				else if (color) fprintf(fp, "\33[4m%.*s\33[0m\n", out, &sel->repr[i]);
				else fprintf(fp, "%.*s\n", out, &sel->repr[i]);
				break;
			case '`':
				fprintf(fp, "%s\n", &sel->repr[i]);
				break;
			case '>':
				fprintf(fp, "%c %.*s\n", sel->type, out, &sel->repr[i]);
				break;
			default:
				if (i == 0) fprintf(fp, "%c %.*s\n", sel->type, out, &sel->repr[i]);
				else fprintf(fp, "  %.*s\n", out, &sel->repr[i]);
		}

		i += out + strspn(&sel->repr[i + out], " ");
	} while (i < (int)size);
}


static void print_text(FILE *fp, SelectorList *list, const char *filter) {
	regex_t re;
	Selector *sel;
	int width, links = 0;

	if (filter && regcomp(&re, filter, REG_NOSUB) != 0) filter = NULL;
	width = get_terminal_width();
	SIMPLEQ_FOREACH(sel, list, next) print_line(fp, sel, filter ? &re : NULL, width, &links);
	if (filter) regfree(&re);
}


/*============================================================================*/
static int tofu(X509 *cert, const char *host, int ask) {
	static char buffer[1024], hex[EVP_MAX_MD_SIZE * 2 + 1];
	static unsigned char md[EVP_MAX_MD_SIZE];
	size_t size = 1, hlen;
	const char *p, *end;
	char *line, *start;
	unsigned int mdlen, i;
	int fd = -1, found = 0, trust = 0;

	if (X509_digest(cert, EVP_sha512(), md, &mdlen) == 0) return 0;

	for (i = 0; i < mdlen; ++i) {
		hex[i * 2] = "0123456789ABCDEF"[md[i] >> 4];
		hex[i * 2 + 1] = "0123456789ABCDEF"[md[i] & 0xf];
	}
	hex[mdlen * 2] = '\0';

	hlen = strlen(host);

	if ((p = map_file("hosts", &fd, &size)) == NULL && size > 0) return 0;
	else if (p != NULL) {
		for (end = p; !found && (start = memmem(end, size - (end - p), host, hlen)) != NULL; end = start + hlen + 1) {
			if (!(found = ((start == p || *(start - 1) == '\n') && size - (start - p) >= hlen + 2 && start[hlen] == ' ' && start[hlen + 1] != '\n'))) continue;
			if (size - (start - p) < hlen + 1 + mdlen * 2 + 1 || start[hlen + 1 + mdlen * 2] != '\n') break;
			if ((trust = memcmp(&start[hlen + 1], hex, mdlen * 2) == 0) || !ask) break;
			if (color) snprintf(buffer, sizeof(buffer), "\33[35mTrust new certificate for `%s`? (y/n)>\33[0m ", host);
			else snprintf(buffer, sizeof(buffer), "Trust new certificate for `%s`? (y/n)> ", host);
			if ((line = bestline(buffer)) != NULL) {
				if (*line == 'y' || *line == 'Y') {
					memcpy(&start[hlen + 1], hex, mdlen * 2);
					trust = 1;
				}
				free(line);
			}
			munmap((void *)p, size);
		}
	}
	if (!found) trust = append_line(fd, "%s %s\n", host, hex);
	close(fd);
	return trust;
}


static SSL *ssl_connect(Selector *sel, SSL_CTX *ctx, int ask) {
	BIO *bio = NULL;
	SSL *ssl = NULL;
	X509 *cert = NULL;
	int fd = -1, ok = 0, err;

	if ((fd = tcp_connect(sel)) == -1) goto out;

	if ((ssl = SSL_new(ctx)) == NULL || (bio = BIO_new_socket(fd, BIO_CLOSE)) == NULL || SSL_set_tlsext_host_name(ssl, sel->host) == 0) {
		error(0, "cannot establish secure connection to `%s`:`%s`", sel->host, sel->port);
		goto out;
	}
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);

	if ((err = SSL_get_error(ssl, SSL_do_handshake(ssl))) != SSL_ERROR_NONE) {
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "cannot establish secure connection to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot establish secure connection to `%s`:`%s`: error %d", sel->host, sel->port, err);
		goto out;
	}

	if ((cert = SSL_get_peer_certificate(ssl)) == NULL) {
		error(0, "cannot establish secure connection to `%s`:`%s`: no peer certificate", sel->host, sel->port);
		goto out;
	}

	if (!(ok = tofu(cert, sel->host, ask))) error(0, "cannot establish secure connection to `%s`:`%s`: bad certificate", sel->host, sel->port);

out:
	if (cert) X509_free(cert);
	if (!ok && ssl) SSL_free(ssl);
	else if (!ok && bio) BIO_free(bio);
	else if (!ok && fd != -1) close(fd);
	return ok ? ssl : NULL;
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


static int ssl_error(Selector *sel, void *c, int err) {
	if ((err = SSL_get_error((SSL *)c, err)) == SSL_ERROR_ZERO_RETURN) return 0;
	if (err == SSL_ERROR_SSL) { error(0, "protocol error while downloading `%s`", sel->url); return 0; }; /* some servers seem to ignore this part of the specification (v0.16.1): "As per RFCs 5246 and 8446, Gemini servers MUST send a TLS `close_notify`" */
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "failed to download `%s`: cancelled", sel->url);
	else error(0, "failed to download `%s`: error %d", sel->url, err);
	return 1;
}


static int ssl_read(void *c, void *buffer, int length) {
	return SSL_read((SSL *)c, buffer, length);
}


static void ssl_close(void *c) {
	SSL_free((SSL *)c);
}


static int save_body(Selector *sel, void *c, FILE *fp) {
	static char buffer[2048];
	size_t total;
	int received, prog = 0;
	for (total = 0; total < SIZE_MAX - sizeof(buffer) && (received = sel->proto->read(c, buffer, sizeof(buffer))) > 0 && fwrite(buffer, 1, received, fp) == (size_t)received; total += received) {
		if ((total > 2048 && total - prog > total / 20)) { fputc('.', stderr); prog = total; }
	}
	if (prog > 0) fputc('\n', stderr);
	if (ferror(fp)) { error(0, "failed to download `%s`: failed to write", sel->url); return 0; }
	return !sel->proto->error(sel, c, received);
}


static int do_download(Selector *sel, SSL **body, char **mime, int ask) {
	static char crtpath[1024], keypath[1024], suffix[1024], buffer[1024], data[2 + 1 + 1024 + 2 + 1]; /* 99 meta\r\n\0 */
	struct stat stbuf;
	const char *home;
	SSL_CTX *ctx = NULL;
	char *crlf, *meta = &data[3], *line, *url;
	int redir, off, len, i, total, received, ret = 40, err = 0;
	SSL *ssl = NULL;

	if ((redir = perm_redirect(sel, NULL)) == 31) return 31;
	else if (redir != 20) goto fail;

	if ((home = getenv("XDG_DATA_HOME")) != NULL) {
		if ((off = snprintf(crtpath, sizeof(crtpath), "%s/gplaces_%s", home, sel->host)) >= (int)sizeof(crtpath)) goto fail;;
	} else if ((home = getenv("HOME")) == NULL || (off = snprintf(crtpath, sizeof(crtpath), "%s/.gplaces_%s", home, sel->host)) >= (int)sizeof(crtpath)) goto fail;

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) goto fail;
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

	if ((ssl = ssl_connect(sel, ctx, ask)) == NULL) goto fail;

	len = snprintf(buffer, sizeof(buffer), "%s\r\n", sel->url);
	if ((err = SSL_get_error(ssl, SSL_write(ssl, buffer, len >= (int)sizeof(buffer) ? (int)sizeof(buffer) - 1 : len))) != SSL_ERROR_NONE) {
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) error(0, "cannot send request to `%s`:`%s`: cancelled", sel->host, sel->port);
		else error(0, "cannot send request to `%s`:`%s`: error %d", sel->host, sel->port, err);
		goto fail;
	}

	for (total = 0; total < (int)sizeof(data) - 1 && (total < 4 || (data[total - 2] != '\r' && data[total - 1] != '\n')) && (received = SSL_read(ssl, &data[total], 1)) > 0; ++total);
	if (received <= 0 && ssl_error(sel, ssl, received)) goto fail;
	else if (total < 4 || data[0] < '1' || data[0] > '6' || data[1] < '0' || data[1] > '9' || (total > 4 && data[2] != ' ') || data[total - 2] != '\r' || data[total - 1] != '\n') { error(0, "failed to download `%s`: invalid status line", sel->url); goto fail; }
	data[total] = '\0';

	crlf = &data[total - 2];
	*crlf = '\0';
	if (meta >= crlf) meta = "";

	switch (data[0]) {
		case '2':
			if (!*meta) goto fail;
			*body = ssl;
			ssl = NULL;
			*mime = meta;
			break;

		case '1':
			if (!ask || !*meta) goto fail;
			if (color) snprintf(buffer, sizeof(buffer), "\33[35m%.*s>\33[0m ", get_terminal_width() - 2, meta);
			else snprintf(buffer, sizeof(buffer), "%.*s> ", get_terminal_width() - 2, meta);
			if (data[1] == '1') bestlineMaskModeEnable();
			if ((line = bestline(buffer)) == NULL) goto fail;
			if (data[1] != '1' && interactive) bestlineHistoryAdd(line);
			if (data[1] == '1') bestlineMaskModeDisable();
			if (!set_input(sel, line)) { free(line); goto fail; }
			free(line);
			if (curl_url_get(sel->cu, CURLUPART_URL, &url, 0) != CURLUE_OK) goto fail;
			curl_free(sel->url); sel->url = url;
			if (data[1] != '1' && interactive) bestlineHistoryAdd(url);
			break;

		case '3':
			if (!*meta) goto fail;
			if (data[1] == '1' && !perm_redirect(sel, meta)) goto fail;
			else if (data[1] != '1' && !redirect(sel, meta, total - 2)) goto fail;
			break;

		case '6':
			if (*meta) error(0, "`%s`: %s", sel->host, meta);
			else error(0, "client certificate is required for `%s`", sel->host);
			if (ask && stat(crtpath, &stbuf) != 0 && errno == ENOENT && stat(keypath, &stbuf) != 0 && errno == ENOENT) {
				if (color) snprintf(buffer, sizeof(buffer), "\33[35mGenerate client certificate for `%s`? (y/n)>\33[0m ", sel->host);
				else snprintf(buffer, sizeof(buffer), "Generate client certificate for `%s`? (y/n)> ", sel->host);
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
	if (ssl) SSL_free(ssl);
	if (ctx) SSL_CTX_free(ctx);
	return ret;
}


static void sigint(int sig) {
	(void)sig;
}


static void *gemini_download(Selector *sel, char **mime, Parser *parser, int ask) {
	SSL *ssl = NULL;
	int status, redirs = 0;

	do {
		status = do_download(sel, &ssl, mime, ask);
		if (status >= 20 && status <= 29) break;
	} while ((status >= 10 && status <= 19) || (status >= 60 && status <= 69) || (status >= 30 && status <= 39 && ++redirs < 5));

	if (ssl != NULL && strncmp(*mime, "text/gemini", 11) == 0) *parser = parse_gemtext_line;
	else if (ssl != NULL && (!interactive || strncmp(*mime, "text/plain", 10) == 0)) *parser = parse_plaintext_line;

	if (redirs == 5) error(0, "too many redirects from `%s`", sel->url);
	return ssl;
}


const Protocol gemini = {"gemini", "1965", ssl_read, ssl_error, ssl_close, gemini_download};


/*============================================================================*/
#if defined(GPLACES_WITH_GOPHER) || defined(GPLACES_WITH_SPARTAN) || defined(GPLACES_WITH_FINGER)
	#include "tcp.c"
#endif
#if defined(GPLACES_WITH_GOPHER) || defined(GPLACES_WITH_GOPHERS)
	#include "gopher.c"
#endif
#ifdef GPLACES_WITH_GOPHERS
	#include "gophers.c"
#endif
#ifdef GPLACES_WITH_SPARTAN
	#include "spartan.c"
#endif
#ifdef GPLACES_WITH_FINGER
	#include "finger.c"
#endif


/*============================================================================*/
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


static void stream_to_handler(Selector *sel, const char *filename) {
	int fds[2];
	char *mime = NULL;
	void *c;
	Parser parser;
	const char *handler;
	FILE *fp;
	pid_t pid;

	if (pipe(fds) == -1) return;
	if (fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0 && (fp = fdopen(fds[1], "w")) != NULL) {
		setbuf(fp, NULL);
		if ((c = sel->proto->download(sel, &mime, &parser, 1)) != NULL) {
			if ((handler = find_mime_handler(mime)) != NULL && (pid = start_handler(handler, filename, sel, fds[0])) > 0) {
				close(fds[0]); fds[0] = -1;
				save_body(sel, c, fp);
				fclose(fp); fp = NULL;
				sel->proto->close(c); /* close the connection while the handler is running */
				reap(handler, pid, 0);
			} else sel->proto->close(c);
		}
		if (fds[0] != -1) close(fds[0]);
		if (fp != NULL) fclose(fp);
	} else {
		close(fds[0]);
		close(fds[1]);
	}
}


static void download_to_file(Selector *sel, const char *def) {
	static char suggestion[256];
	FILE *fp;
	char *mime = NULL, *input = NULL, *download_dir;
	const char *filename = def;
	void *c;
	Parser parser;
	size_t len;
	int ret = 0;

	if (def != NULL && strcmp(def, "-") == 0) { stream_to_handler(sel, def); return; }

	if (def == NULL) {
		def = get_filename(sel, &len);
		if (((download_dir = set_var(&variables, "DOWNLOAD_DIRECTORY", NULL)) != NULL && *download_dir != '\0') || (download_dir = getenv("XDG_DOWNLOAD_DIR")) != NULL) snprintf(suggestion, sizeof(suggestion), "%s/%.*s", download_dir, (int)len, def);
		else if ((download_dir = getenv("HOME")) != NULL) {
			snprintf(suggestion, sizeof(suggestion), "%s/Downloads", download_dir);
			if (access(suggestion, F_OK) == 0) snprintf(suggestion, sizeof(suggestion), "%s/Downloads/%.*s", download_dir, (int)len, def);
			else snprintf(suggestion, sizeof(suggestion), "%s/%.*s", download_dir, (int)len, def);
		} else snprintf(suggestion, sizeof(suggestion), "./%.*s", (int)len, def);
		if ((input = bestlineInit("enter filename: ", suggestion)) == NULL) return;
		if (*input != '\0') filename = input;
		else filename = suggestion;
	}
	if ((fp = fopen(filename, "wb")) == NULL) error(0, "cannot create file `%s`: %s", filename, strerror(errno));
	else {
		if ((c = sel->proto->download(sel, &mime, &parser, 1)) != NULL) {
			ret = save_body(sel, c, fp);
			sel->proto->close(c);
		}

		fclose(fp);
		if (!ret) unlink(filename);
	}
	free(input);
}


static void save_and_handle(Selector *sel, void *c, const char *mime) {
	static char filename[1024];
	FILE *fp = NULL;
	const char *tmpdir, *handler = NULL;
	int fd = -1;

	if ((handler = find_mime_handler(mime)) == NULL) return;
#ifdef GPLACES_USE_FLATPAK_SPAWN
	if ((tmpdir = getenv("XDG_DATA_HOME")) == NULL) tmpdir = "/tmp";
#else
	if ((tmpdir = getenv("TMPDIR")) == NULL) tmpdir = "/tmp";
#endif
	snprintf(filename, sizeof(filename), "%s/gplaces.XXXXXXXX", tmpdir);
	if ((fd = mkstemp(filename)) == -1 || (fp = fdopen(fd, "w")) == NULL) error(0, "cannot create temporary file: %s", strerror(errno));
	else if (save_body(sel, c, fp) && fflush(fp) == 0) execute_handler(handler, filename, sel);

	if (fp != NULL) fclose(fp);
	if (fd != -1) {
		if (fp == NULL) close(fd);
		unlink(filename);
	}
}


static SelectorList download_text(Selector *sel, int ask, int handle, int print) {
	static char buffer[LINE_MAX];
	SelectorList list = SIMPLEQ_HEAD_INITIALIZER(list);
	Parser parser = NULL;
	Selector *it;
	char *mime, *p = NULL, *start, *end;
	void *c = NULL;
	size_t parsed, length = 0, total = 0, prog = 0;
	int received, pre = 0, width, ok = 0, links = 0;

	if ((c = sel->proto->download(sel, &mime, &parser, ask)) == NULL) goto out;
	if (parser == NULL) {
		if (handle) save_and_handle(sel, c, mime);
		goto out;
	}
	width = get_terminal_width();
	while ((received = sel->proto->read(c, &buffer[length], sizeof(buffer) - length)) > 0) {
		for (length += received, parsed = 0, start = buffer; start < buffer + length; parsed += end - start + 1, start = end + 1) {
			if ((end = memchr(start, '\n', length - parsed)) == NULL) {
				if (parsed > 0 || length < sizeof(buffer)) break; /* if we still don't have the end of the line, receive more */
				end = &buffer[sizeof(buffer) - 1]; /* if the buffer is full and we haven't found a \n, terminate the line */
			}
			if (end > start && end[-1] == '\r') end[-1] = '\0';
			else *end = '\0';
			parser((parsed == 0 && strncmp(start, "\xef\xbb\xbf", 3) == 0) ? start + 3: start, &pre, &it, &list);
			if (print && it) print_line(stdout, it, NULL, width, &links);
		}
		length -= parsed;
		memmove(buffer, &buffer[parsed], length);
		buffer[length] = '\0';
		total += received;
		if (!print && total > 2048 && total - prog > total / 20) { fputc('.', stderr); prog = total; }
		if (total > SIZE_MAX - sizeof(buffer)) break;
	}
	if (prog > 0) fputc('\n', stderr);
	if (!(ok = (received <= 0 && !sel->proto->error(sel, c, received)))) goto out;
	if (length > 0) {
		parser((parsed == 0 && strncmp(buffer, "\xef\xbb\xbf", 3) == 0) ? buffer + 3: buffer, &pre, &it, &list);
		if (print && it) print_line(stdout, it, NULL, width, &links);
	}

out:
	free(p);
	if (c != NULL) sel->proto->close(c);
	if (!ok) { free_selectors(&list); SIMPLEQ_INIT(&list); }
	return list;
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
		print_text(fp, list, NULL);
		fclose(fp);
	}

	reap(pager, pid, 1);
}


static void navigate(Selector *to) {
	const char *handler = NULL, *ext;
	SelectorList new = SIMPLEQ_HEAD_INITIALIZER(new);
	FILE *fp;
#ifdef GPLACES_USE_LIBMAGIC
	magic_t mag;
#endif
	const char *mime = NULL;
	int plain = 0, gemtext = 0, off = 0;

	if (!strcmp(to->scheme, "file")) {
		if ((ext = strrchr(to->path, '.')) == NULL || (!(plain = (strcmp(ext, ".txt") == 0)) && !(gemtext = (strcmp(ext, ".gmi") == 0)))) {
#ifdef GPLACES_USE_LIBMAGIC
			if ((mag = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS | MAGIC_ERROR)) == NULL) return;
			if (magic_load(mag, NULL) == 0 && (mime = magic_file(mag, to->path)) != NULL && !(plain = (strncmp(mime, "text/plain", 10) == 0)) && !(gemtext = (strncmp(mime, "text/gemini", 11) == 0))) handler = find_mime_handler(mime);
			magic_close(mag);
#endif
			if (mime == NULL) error(0, "unable to detect the MIME type of %s", to->path);
		}
		if (!plain && !gemtext) goto handle;
		if ((fp = fopen(to->path, "r")) == NULL) return;
		new = parse_file(fp, plain ? parse_plaintext_line : parse_gemtext_line);
		fclose(fp);
		off = 4;
	} else if (to->proto == NULL) {
		handler = find_mime_handler(to->scheme);
		goto handle;
	} else {
		new = download_text(to, interactive, 1, 1);
		off = strlen(to->scheme);
	}

	if (SIMPLEQ_EMPTY(&new)) return;
	if (color) snprintf(prompt, sizeof(prompt), "\33[35m%s>\33[0m ", to->url + off + 3);
	else snprintf(prompt, sizeof(prompt), "%s> ", to->url + off + 3);
	free(current);
	current = str_copy(to->url);
	free_selectors(&menu);
	menu = new;
	if (interactive) page_gemtext(&menu);
	return;

handle:
	if (handler) execute_handler(handler, to->url, to);
}


/*============================================================================*/
static const Help gemini_help[] = {
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
	const char *filter;
	if ((filter = next_token(&line)) == NULL) page_gemtext(&menu);
	print_text(stdout, &menu, filter);
}


static void cmd_save(char *line) {
	char *id, *path, *end;
	Selector *to;
	long index;
	if ((id = next_token(&line)) == NULL) return;
	path = next_token(&line);
	if ((index = strtol(id, &end, 10)) > 0 && index < INT_MAX && *end == '\0' && (to = find_selector(&menu, (int)index)) != NULL && parse_url(to, current, NULL)) download_to_file(to, path);
	else if (index == LONG_MIN || index == LONG_MAX || *end != '\0') {
		to = new_selector('l');
		if (copy_url(to, id) && parse_url(to, NULL, NULL)) download_to_file(to, path);
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
				return;
			}
		}
		return;
	}

	puts("available commands, type `help <command>` to get more information");
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
	char *url = next_token(&line);
	if (url) {
		Selector *sel = new_selector('l');
		if (copy_url(sel, url)) SIMPLEQ_INSERT_TAIL(&subscriptions, sel, next);
		else free_selector(sel);
	} else {
		t = time(NULL);
		tm = gmtime(&t);
		strftime(ts, sizeof(ts), "%Y-%m-%d", tm);

		SIMPLEQ_FOREACH(sel, &subscriptions, next) {
			if (sel->host == NULL && !parse_url(sel, NULL, NULL)) continue;

			list = download_text(sel, 0, 0, 0);
			if (SIMPLEQ_EMPTY(&list)) continue;

			copy = new_selector('l');
			if (!copy_url(copy, sel->url)) { free_selector(copy); free_selectors(&list); continue; }

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == '#' && it->level == 1) {
					copy->repr = str_copy(it->repr);
					break;
				}
			}

			if (copy->repr == NULL) copy->repr = str_copy(sel->url);

			SIMPLEQ_INSERT_TAIL(&feed, copy, next);

			SIMPLEQ_FOREACH(it, &list, next) {
				if (it->type == 'l' && !strncmp(it->repr, ts, 10)) {
					copy = new_selector(it->type);
					if (!copy_url(copy, it->rawurl) || !parse_url(copy, sel->url, NULL)) { free_selector(copy); continue; }
					copy->repr = str_copy(it->repr);
					SIMPLEQ_INSERT_TAIL(&feed, copy, next);
				}
			}

			free_selectors(&list);
		}
		if (SIMPLEQ_EMPTY(&feed)) return;
		free_selectors(&menu);
		menu = feed;
		print_text(stdout, &feed, NULL);
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
	char *copy, *line, *token, *var, *url, *end;
	long index;

	if ((index = strtol(input, &end, 10)) > 0 && index < INT_MAX && *end == '\0' && (to = find_selector(&menu, (int)index)) != NULL) {
		if ((to->url || parse_url(to, current, NULL)) && interactive) bestlineHistoryAdd(to->url);
		else if (interactive) bestlineHistoryAdd(input);
		navigate(to);
		return;
	} else if (index > 0 && index != LONG_MAX && *end == '\0') return;

	if (interactive) bestlineHistoryAdd(input);

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
		to = new_selector('l');
		if (copy_url(to, url) && parse_url(to, NULL, next_token(&line))) navigate(to);
		else if (filename == NULL) error(0, "unknown command `%s`", token);
		else error(0, "unknown command `%s` in file `%s` at line %d", token, filename, line_no);
		free_selector(to);
	}

	free(copy);
}


static void shell_name_completion(const char *text, bestlineCompletions *lc) {
	const Command *cmd;
	const Variable *var;
	Selector *sel;
	long index;
	char *end;
	int len;

	if ((index = strtol(text, &end, 10)) > 0 && index < INT_MAX && *end == '\0' && (sel = find_selector(&menu, (int)index)) != NULL && (sel->url != NULL || parse_url(sel, current, NULL))) bestlineAddCompletion(lc,sel->url);

	len = strlen(text);

	for (cmd = gemini_commands; cmd->name; ++cmd)
		if (!strncasecmp(cmd->name, text, len)) bestlineAddCompletion(lc, cmd->name);

	LIST_FOREACH(var, &variables, next)
		if (!strncasecmp(var->name, text, len)) bestlineAddCompletion(lc, var->name);
}


static char *shell_hints(const char *buf, const char **ansi1, const char **ansi2) {
	static char hint[1024];
	Selector *sel;
	const char *val, *pos;
	char *end;
	long index;
	int links = 0;
	if (!color) *ansi1 = *ansi2 = "";
	if (strcspn(buf, " ") == 0) {
		SIMPLEQ_FOREACH(sel, &menu, next) if (sel->type == 'l') ++links;
		if (links > 1) {
			snprintf(hint, sizeof(hint), "1-%d, URL, variable or command", links);
			return hint;
		} else if (links == 1) return "1, URL, variable or command";
		else return "URL, variable or command; type `help` for help";
	}
	if ((pos = strrchr(buf, ' ')) != NULL) buf = &pos[1];
	if ((index = strtol(buf, &end, 10)) > 0 && index < INT_MAX && *end == '\0') {
		if ((sel = find_selector(&menu, (int)index)) == NULL) return NULL;
		if (strncmp(sel->rawurl, "gemini://", 9) == 0) snprintf(hint, sizeof(hint), " %s", &sel->rawurl[9]);
		else snprintf(hint, sizeof(hint), " %s", sel->rawurl);
	} else if ((val = set_var(&variables, buf, NULL)) != NULL) {
		if (strncmp(val, "gemini://", 9) == 0) snprintf(hint, sizeof(hint), " %s", &val[9]);
		else if (strncmp(val, "file://", 7) == 0) snprintf(hint, sizeof(hint), " %s", &val[7]);
		else snprintf(hint, sizeof(hint), " %s", val);
	} else return NULL;
	return hint;
}


static void shell(int argc, char **argv) {
	static char path[1024];
	const char *home = NULL;
	char *line;

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
		if ((line = bestline(prompt)) == NULL) break;
		bestlineSetHintsCallback(NULL);
		eval(line, NULL, 0);
		free(line);
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
				fprintf(stderr, "usage: gplaces [-r rc-file] [url]\n");
				exit(EXIT_SUCCESS);
		}
	}
	return rcfile;
}


static void quit_client() {
	free_variables(&variables);
	free_selectors(&subscriptions);
	free_selectors(&menu);
	free(current);
	if (interactive) puts("\33[0m");
}


int main(int argc, char **argv) {
	struct sigaction sa = {.sa_handler = sigint};

	setlocale(LC_ALL, "");
	atexit(quit_client);
	setlinebuf(stdout); /* if stdout is a file, flush after every line */
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	SSL_library_init();
	SSL_load_error_strings();

	interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
	if (!(color = interactive && (getenv("NO_COLOR") == NULL))) memcpy(prompt, "> ", 3);

	load_rc_files(parse_arguments(argc, argv));

	if (interactive) puts(
		"gplaces - "GPLACES_VERSION"  Copyright (C) 2022, 2023  Dima Krasner\n" \
		"Based on delve 0.15.4  Copyright (C) 2019  Sebastian Steinhauer\n" \
		"This program is free software and comes with ABSOLUTELY NO WARRANTY;\n" \
		"see "PREFIX"/share/doc/gplaces/LICENSE for details.\n"
	);

	shell(argc, argv);

	return 0;
}
/* vim: set ts=4 sw=4 noexpandtab: */
