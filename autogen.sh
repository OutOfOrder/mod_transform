#!/bin/sh
# autogen.sh - generates configure using the autotools
export WANT_AUTOCONF=2.5

LIBTOOLIZE=$(which libtoolize || which glibtoolize)
$LIBTOOLIZE --force --copy
aclocal -I m4
autoheader
automake --add-missing --copy --foreign
autoconf
rm -rf autom4te.cache
