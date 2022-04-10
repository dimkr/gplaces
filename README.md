# gplaces - a simple terminal Gemini client

Because Gemini deserves a light client with a high power to weight ratio!

gplaces is named after [Going Places](https://en.wikipedia.org/wiki/Going_Places_(Herb_Alpert_and_the_Tijuana_Brass_album)), the 1965 album by Herb Alpert and The Tijuana Brass.

The gplaces logo is an artist's impression of a Gemini VII capsule with the red accents of a [Humes and Berg](https://humesandberg.com) Stonelined straight trumpet mute. Sort of.

## Overview
- configurable MIME type handlers
- "powerful" shell
- bookmarks
- variables
- command aliases
- VT100 compatible with ANSI escape sequences
- no exotic external dependencies, no NIH
	- ~GNU readline is fully optional~ bestline
	- openssl
	- libcurl
- SSH-style TOFU with ~/.gplaces_hosts
- about *1k lines* of *C* code

## How to compile?
- clone this git repo
- just type `make` on any Unix compatible system
	- currently tested on
		- Linux
- type `make install` to install it on the system (defaults to /usr/local)

## How to contribute?
- send me pull-requests and I'll review and merge them :)
- if you wish to appear on the `help authors` command just add yourself there

## License
- [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)

## Statistic
Language|files|blank|comment|code
:-------|-------:|-------:|-------:|-------:
C|1|238|34|999

## Help
Just type `help` when the client is running.
