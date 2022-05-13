# gplaces - a simple terminal Gemini client

Because Gemini deserves a light client with a high power to weight ratio!

gplaces is named after [Going Places](https://en.wikipedia.org/wiki/Going_Places_(Herb_Alpert_and_the_Tijuana_Brass_album)), the 1965 album by Herb Alpert and The Tijuana Brass. The "o" is omitted from the executable name so it doesn't mess up tab completion for Gopher users and Go developers.

The gplaces logo is an artist's impression of a Gemini VII capsule with the red accents of a [Humes and Berg](https://humesandberg.com) Stonelined straight trumpet mute. Sort of.

gplaces is originally a Gemini port of the [delve](https://github.com/kieselsteini/delve) Gopher client by Sebastian Steinhauer.

## Features
- configurable MIME type handlers
- "powerful" shell with tab completion
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
	- libidn2 or libidn (optional)
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
- just type `make` or `make WITH_LIBIDN2=0 WITH_LIBIDN=0 WITH_LIBMAGIC=0` on any Unix compatible system
	- currently tested on
		- Linux
- type `make install` to install it on the system (defaults to /usr/local)

## How to use?

    > gemini.circumlunar.space

to show a Gemini page, type its URL, press `ENTER` and gplaces will stream the page contents to the terminal.

to abort the download, press `CTRL+c`.

when the download is finished, gplaces will display the downloaded page using less(1), the same tool man(1) uses to display man pages.

    `less -r` has exited with exit status 0
    gemini.circumlunar.space/> 

use the arrow keys to scroll, `/` to search and `q` to exit less and return to the gplaces prompt.

    (reverse-i-search `g') gemini.circumlunar.space

in addition, gplaces adds the page URL to the history: use the `Up` and `Down` keys to navigate through the history, or `CTRL+r` to search through it. these are only three examples of key bindings from shells like bash(1) which work in gplaces, too.

gplaces does not display non-Gemtext files: instead, it downloads them to temporary files and runs external "handler" programs (one for each file type) defined in the gplaces configuration file.

    > save gemini.circumlunar.space/docs/specification.gmi
    enter filename (press ENTER for `/home/user/Downloads/specification.gmi`):

to download a file instead of displaying it or saving it to a temporary file, type `save`, followed by its URL, then press `ENTER`.

    gemini.circumlunar.space/> 2 docs/

gplaces associates a number with each link in the last viewed page. type the number of a link to show its URL, then press `ENTER` to follow it.

to edit the URL of a link, type the link number, press `Tab`, edit the URL and press `ENTER`. for example, this is useful if a link leads to a post in another gemlog, but you want to see its homepage.

    gemini.circumlunar.space/docs/> save 2
    enter filename (press ENTER for `/home/user/Downloads/specification.gmi`):

this number can be used to download the link, too.

    gemini.circumlunar.space/docs/> search
    Search query> gplaces

the gplaces configuration file allows you to define short aliases for URLs you visit often. for example, the default configuration file defines the `home` alias for the Gemini project homepage and the `search` alias for a Gemini search engine. type `search` and press `ENTER` to search geminispace.

to show a feed of new posts, type `sub`, then press `ENTER`. the list of URLs gplaces is "subscribed" to is defined in the configuration file.

to exit gplaces, press `CTRL+d`.

additional documentation and more details are available in `man gplaces`. type `help` and press `ENTER` to see short descriptions of available commands.

## How to contribute?
- send me pull-requests and I'll review and merge them :)
- if you wish to appear on the `help authors` command just add yourself there

## License
- [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)

## Statistic
Language|files|blank|comment|code
:-------|-------:|-------:|-------:|-------:
C|1|228|57|1029
