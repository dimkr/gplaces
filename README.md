# gplaces - a simple terminal Gemini client

Because Gemini deserves a light client with a high power to weight ratio!

gplaces is named after [Going Places](https://en.wikipedia.org/wiki/Going_Places_(Herb_Alpert_and_the_Tijuana_Brass_album)), the 1965 album by Herb Alpert and The Tijuana Brass. The "o" is omitted from the executable name so it doesn't mess up tab completion for Gopher users and Go developers.

The gplaces logo is an artist's impression of a Gemini VII capsule with the red accents of a [Humes and Berg](https://humesandberg.com) Stonelined straight trumpet mute. Sort of.

gplaces is originally a Gemini port of the [delve](https://github.com/kieselsteini/delve) Gopher client by Sebastian Steinhauer.

## Overview
- configurable MIME type handlers
- "powerful" shell
- ~bookmarks~ use aliases
- subscriptions
	- only [simple subscriptions](https://gemini.circumlunar.space/docs/companion/subscription.gmi) are supported, to avoid [XML parsing](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=xml)
- variables
- ~command aliases~ use variables
- sh-style history with $XDG_DATA_HOME/gplaces_history or ~/.gplaces_history
- VT100 compatible with ANSI escape sequences
- no exotic external dependencies, no NIH
	- ~GNU readline is fully optional~ bestline
	- openssl or libressl
	- libcurl
	- libmagic (optional)
- SSH-style TOFU with $XDG_DATA_HOME/gplaces_hosts or ~/.gplaces_hosts
- client certificates support via $XDG_DATA_HOME/gplaces_$host$path.{crt,key} or ~/.gplaces_$host$path.{crt,key}
	- auto-generation with user consent
	- strict implementation, [the certificate for /foo is used for /foo{,/,/bar}](https://gitlab.com/gemini-specification/protocol/-/blob/75fdc58c6f76a8172ccd7dbf90824dd6146ed0b6/specification.gmi#L116)
- ~internal~ configurable external pager for text & menus
- support for non-interactive operation
- UTF-8 line wrapping of lists and quotes
- hackable, about *1k lines* of *C* code
- ~100K executable when built with -O3 and -Wl,-s on x86_64

## How to install?
- [using Flatpak](https://flathub.org/apps/details/com.github.dimkr.gplaces): `flatpak install flathub com.github.dimkr.gplaces`
- compile yourself

## How to compile?
- clone this git repo
- just type `make` or `make WITH_LIBMAGIC=0` on any Unix compatible system
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
C|1|224|58|1032

## Help
Just type `help` when the client is running.
