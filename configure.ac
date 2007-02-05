dnl Required initializer
AC_INIT(mod_transform, 0.7.0)
OOO_CONFIG_NICE(config.nice)
AC_PREREQ(2.53)
AC_CONFIG_SRCDIR([src/mod_transform.c])
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER([include/mod_transform_config.h:config.in])

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_LIBTOOL


AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)
LIBTOOL="`${APR_CONFIG} --apr-libtool`"
AC_SUBST(LIBTOOL)

AM_PATH_XML2(2.6.11,
    ,
    AC_MSG_ERROR([could not find libxml2])
)

AM_PATH_XSLT(1.1.5,
    ,
    AC_MSG_ERROR([could not find libxslt])
)

AC_MSG_CHECKING([for mod_depends.h])
if test -f ${AP_INCLUDEDIR}/mod_depends.h; then
    AC_MSG_RESULT([found it!])
else
    AC_MSG_RESULT(no)
    AC_MSG_WARN([** Please install mod_depends from http://www.outoforder.cc])
    AC_MSG_ERROR([*** mod_depends is required for mod_transform.])
fi 

dnl {{{ libapreq2
AC_MSG_CHECKING([for libapreq2])
if which apreq2-config &>/dev/null; then
	APREQ2_VERSION=`apreq2-config --library-version`
	APREQ2_CFLAGS=`apreq2-config --includes`
	APREQ2_LIBS=`apreq2-config --link-libtool --ldflags --libs`

	AC_MSG_RESULT([yes (version $APREQ2_VERSION)])

	AC_SUBST(APREQ2_VERSION)
	AC_SUBST(APREQ2_CFLAGS)
	AC_SUBST(APREQ2_LIBS)
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([*** libapreq2 is required for mod_transform to compile.])
	AC_MSG_ERROR([*** Please download it from: http://httpd.apache.org/apreq/])
fi
dnl }}}

MODULE_CFLAGS="${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"

AC_SUBST(MODULE_CFLAGS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_transform"
echo ""
echo "   * Apache Dodules Directory:    $AP_LIBEXECDIR"
echo ""
echo "---"
