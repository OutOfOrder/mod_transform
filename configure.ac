
AC_INIT
AC_CONFIG_SRCDIR([src/mod_transform.c])
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE(mod_transform, 0.1.0)
AM_CONFIG_HEADER([include/mod_transform_config.h:config.in])

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AM_PROG_LIBTOOL

CHECK_APACHE()

AM_PATH_XSLT(1.1.0,
    ,
    AC_MSG_ERROR([could not find libxslt]) )

AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
if test "x$PKG_CONFIG" = "xno"; then
        AC_MSG_ERROR([You need to install pkg-config])
fi

MODULE_CFLAGS="${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"

AC_SUBST(MODULE_CFLAGS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
OOO_CONFIG_NICE(config.nice)

echo "---"
echo "Configuration summary for mod_transform"
echo ""
echo "   * Apache modules directory = $AP_LIBEXECDIR"
echo ""
echo "---"
