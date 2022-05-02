#!/bin/sh -xe

HERE=`pwd`

curl -L https://github.com/dimkr/toolchains/releases/latest/download/$1.tar.gz | sudo tar -xzf - -C /
curl -Lo papawify-xz https://github.com/dimkr/papaw/releases/latest/download/papawify-xz
curl -Lo papaw-xz-${1%%-*} https://github.com/dimkr/papaw/releases/latest/download/papaw-xz-${1%%-*}

. /opt/x-tools/$1/activate
export MAKEFLAGS=-j`nproc`

curl https://curl.se/`curl -s https://curl.se/download/ | fgrep -m1 download/curl | cut -f 4 -d \"` | tar -xjf- -C /tmp
curl https://www.openssl.org/source/`curl https://www.openssl.org/source/ | fgrep -m1 openssl-3 | cut -f 2 -d \"` | tar -xzf- -C /tmp

cd /tmp/openssl-3.*
CC=$1-gcc ./Configure enable-ec_nistp_64_gcc_128 no-ssl3 no-comp no-dtls no-pic no-shared no-tests --prefix=/usr linux-${1%%-*}
make
export CFLAGS="$CFLAGS -I`pwd`/include" LDFLAGS="$LDFLAGS -L`pwd`" PKG_CONFIG_PATH="`pwd`"

cd ../curl-*
./configure --host=$1 --disable-shared --without-ssl
make
export CFLAGS="$CFLAGS -I`pwd`/include" LDFLAGS="$LDFLAGS -L`pwd`/lib/.libs" PKG_CONFIG_PATH="$PKG_CONFIG_PATH:`pwd`" 

cd "$HERE"
make CC=$1-gcc WITH_LIBMAGIC=0
$1-strip -R .note -R .comment gplaces

python3 papawify-xz papaw-xz-${1%%-*} gplaces gplaces-packed