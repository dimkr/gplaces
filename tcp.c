/*
================================================================================

	gplaces - a simple terminal Gemini client
    Copyright (C) 2022, 2023  Dima Krasner

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
static int tcp_read(void *c, void *buffer, int length) {
	return (int)recv((int)(intptr_t)c, buffer, (size_t)length, 0);
}


static int tcp_peek(void *c, void *buffer, int length) {
	return (int)recv((int)(intptr_t)c, buffer, (size_t)length, MSG_PEEK);
}


static ssize_t sendall(int sockfd, const void *buf, size_t len, int flags) {
	ssize_t sent = 0, total;
	for (total = 0; total < (ssize_t)len && (sent = send(sockfd, (char *)buf + total, len - total, flags)) > 0; total += sent);
	return sent <= 0 ? sent : total;
}