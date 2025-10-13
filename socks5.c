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
static int socks5_tcp_connect(const URL *proxy, const URL *url) {
	static char buf[255];
	static const struct {
		uint8_t ver;
		uint8_t nmethods;
		uint8_t methods;
	} neg = {
		.ver = 5,
		.nmethods = 1,
		.methods = 0,
	};
	struct {
		uint8_t ver;
		uint8_t method;
	} sel;
	struct {
		uint8_t ver;
		uint8_t cmd;
		uint8_t rsv;
		uint8_t atyp;
	} cmd = {
		.ver = 5,
		.cmd = 1,
		.atyp = 3,
	};
	struct {
		uint8_t ver;
		uint8_t rep;
		uint8_t rsv;
		uint8_t atyp;
	} reply;
	size_t len;
	uint8_t blen;
	char *endptr = NULL;
	long l;
	uint16_t port;
	int s;

	len = strlen(url->host);
	if (len > UINT8_MAX) {
		error(0, "host `%s` is too long", url->host);
		return -1;
	}

	if ((l = strtol(url->port, NULL, 10)) < 0 || l > UINT16_MAX || endptr != NULL) {
		error(0, "invalid port in `%s`", proxy->url);
		return -1;
	}

	if ((s = socket_connect(proxy, SOCK_STREAM)) < 0) return -1;

	if (sendall(s, &neg, sizeof(neg), MSG_NOSIGNAL) != sizeof(neg) || recvall(s, &sel, sizeof(sel), MSG_NOSIGNAL) != sizeof(sel)) {
		error(0, "failed to negotiate with `%s`", proxy->url);
		close(s);
		return -1;
	}

	if (sel.ver != 5 || sel.method != 0) {
		error(0, "refused by `%s`", proxy->url);
		close(s);
		return -1;
	}

	if (sendall(s, &cmd, sizeof(cmd), MSG_NOSIGNAL) != sizeof(cmd)) {
		error(0, "failed to command `%s`", proxy->url);
		close(s);
		return -1;
	}

	blen = (uint8_t)len;
	if (sendall(s, &blen, sizeof(blen), MSG_NOSIGNAL) != sizeof(blen) || sendall(s, url->host, len, MSG_NOSIGNAL) != (ssize_t)len) {
		error(0, "failed to send host to `%s`", proxy->url);
		close(s);
		return -1;
	}

	port = htons((uint16_t)l);
	if (sendall(s, &port, sizeof(port), MSG_NOSIGNAL) != sizeof(port)) {
		error(0, "failed to send port to `%s`", proxy->url);
		close(s);
		return -1;
	}

	if (recvall(s, &reply, sizeof(reply), MSG_NOSIGNAL) != sizeof(reply)) {
		error(0, "failed to receive reply from `%s`", proxy->url);
		close(s);
		return -1;
	}

	if (reply.rep != 0) {
		error(0, "failed to connect via `%s`: %02x", proxy->url, reply.rep);
		close(s);
		return -1;
	}

	switch (reply.atyp) {
		case 1:
			if (recvall(s, buf, sizeof(struct in_addr) + sizeof(uint16_t), MSG_NOSIGNAL) != sizeof(struct in_addr) + sizeof(uint16_t)) {
				error(0, "failed to receive IPv4 address from `%s`", proxy->url);
				close(s);
				return -1;
			}

			break;

		case 3:
			if (recvall(s, buf, 1, MSG_NOSIGNAL) != 1) {
				error(0, "failed to receive domain length from `%s`", proxy->url);
				close(s);
				return -1;
			}

			blen = buf[0];
			if (recvall(s, buf, blen + sizeof(uint16_t), MSG_NOSIGNAL) != (ssize_t)(blen + sizeof(uint16_t))) {
				error(0, "failed to receive domain from `%s`", proxy->url);
				close(s);
				return -1;
			}

			break;

		case 4:
			if (recvall(s, buf, sizeof(struct in6_addr) + sizeof(uint16_t), MSG_NOSIGNAL) != sizeof(struct in6_addr) + sizeof(uint16_t)) {
				error(0, "failed to receive IPv6 address from `%s`", proxy->url);
				close(s);
				return -1;
			}

			break;

		default:
			error(0, "invalid address type returned by `%s`: %02x", proxy->url, reply.atyp);
			close(s);
			return -1;
	}

	return s;
}
