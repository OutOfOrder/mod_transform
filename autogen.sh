#!/bin/sh
# autogen.sh - generates configure using the autotools
# $Id: autogen.sh,v 1.1 2004/03/04 08:12:13 firechipmunk Exp $
export WANT_AUTOCONF=2.5

libtoolize --force --copy
aclocal-1.9 -I m4
autoheader
automake-1.9 --add-missing --copy --foreign
autoconf
rm -rf autom4te.cache
