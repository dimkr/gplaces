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
static int socket_error(const URL *url, void *c, int err) {
	(void)c;
	if (err == 0) return 0;
	if (errno == EAGAIN || errno == EWOULDBLOCK) error(0, "failed to download `%s`: cancelled", url->url);
	else error(0, "failed to download `%s`: %s", url->url, strerror(errno));
	return 1;
}
