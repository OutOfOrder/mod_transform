AC_INIT
AC_CONFIG_SRCDIR([src/mod_xmltransform.c])
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE(mod_xmltransform, 0.1.0)
AM_CONFIG_HEADER([include/mod_xmltransform_config.h:config.in])

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# check for --with-apxs
AC_MSG_CHECKING(for --with-apxs)
AC_ARG_WITH(apxs, [  --with-apxs=PATH        Path to apxs],
[
  if test -x "$withval"
  then
    AC_MSG_RESULT([$withval executable, good])
    APXS=$withval
  else
    echo
    AC_MSG_ERROR([$withval not found or not executable])
  fi
],
AC_MSG_RESULT(no))

# if no apxs found yet, check /usr/local/apache/sbin
# since it's the default Apache location
if test -z "$APXS"; then
  AC_MSG_CHECKING(for apxs in /usr/local/apache/sbin)
  if test -x /usr/local/apache/sbin/apxs; then
    APXS=/usr/local/apache/sbin/apxs
    AC_MSG_RESULT([found, we'll use this. Use --with-apxs to specify another.])    
  else
    AC_MSG_RESULT(no)
  fi
fi

if test -z "$APXS"; then
  AC_MSG_CHECKING(for apxs in /usr/local/apache2/bin)
  if test -x /usr/local/apache2/bin/apxs; then
    APXS=/usr/local/apache2/bin/apxs
    AC_MSG_RESULT([found, we'll use this. Use --with-apxs to specify another.])
  else
    AC_MSG_RESULT(no)
  fi
fi

if test -z "$APXS"; then
  AC_MSG_CHECKING(for apxs in /usr/sbin)
  if test -x /usr/sbin/apxs; then
    APXS=/usr/sbin/apxs
    AC_MSG_RESULT([found, we'll use this. Use --with-apxs to specify another.])
  else
    AC_MSG_RESULT(no)
  fi
fi

# last resort
if test -z "$APXS"; then
  AC_MSG_CHECKING(for apxs in your PATH)
  AC_PATH_PROG(APXS, apxs)
  if test -n "$APXS"; then
    AC_MSG_RESULT([found $APXS, we'll use this. Use --with-apxs to specify another.])
  fi
fi

if test -z "$APXS"; then
  AC_MSG_ERROR([**** apxs was not found, DSO compilation will not be available.])
fi

# determine LIBEXEC
AC_MSG_CHECKING(for Apache libexec directory)
LIBEXECDIR=`${APXS} -q LIBEXECDIR`
AC_MSG_RESULT($LIBEXECDIR)

# determine INCLUDES
AC_MSG_CHECKING([for Apache include directory])
AP_INCLUDES="-I`${APXS} -q INCLUDEDIR`"
AC_MSG_RESULT($AP_INCLUDES)
CFLAGS="${CFLAGS} $AP_INCLUDES"

AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
if test "x$PKG_CONFIG" = "xno"; then
        AC_MSG_ERROR([You need to install pkg-config])
fi

PKG_PATH=

AC_SUBST(LIBEXECDIR)
AC_SUBST(AP_INCLUDES)
AC_SUBST(CFLAGS)
AC_SUBST(APXS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_xmltransform"
echo ""
echo "   * Apache modules directory = $LIBEXECDIR"
echo "   * libxslt CFLAGS = $XSLT_INCLUDES"
echo "   * libxslt LDFLAGS = $XSLT_LIBS"
echo ""
echo "---"
