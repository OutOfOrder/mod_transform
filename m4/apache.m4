
dnl Check for Apache, APR and APU
dnl CHECK_PATH_APACHE()
AC_DEFUN(CHECK_APACHE,
[dnl

AC_MSG_CHECKING(for --with-apxs)
AC_ARG_WITH(
	apxs,
	[AC_HELP_STRING([--with-apxs=PATH],[Path to apxs])],
	[
    if test -x "$withval"
      then
      AC_MSG_RESULT([$withval executable, good])
      APXS_BIN=$withval
    else
      echo
      AC_MSG_ERROR([$withval not found or not executable])
    fi
    ],
	AC_MSG_RESULT(no))

# if no apxs found yet, check /usr/local/apache/sbin
# since it's the default Apache location


if test -z "$APXS_BIN"; then
	test_paths="/usr/local/apache/sbin /usr/local/apache/bin /usr/local/apache2/bin"
	test_paths="${test_paths} /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin"
	for x in $test_paths ; do
		AC_MSG_CHECKING(for apxs in $x)
	  	if test -x "${x}/apxs"; then
	    	APXS_BIN="${x}/apxs"
			AC_MSG_RESULT([found it! Use --with-apxs to specify another.])
			break
		else
			AC_MSG_RESULT(no)
		fi
	done
fi

# last resort
if test -z "$APXS_BIN"; then
  AC_MSG_CHECKING(for apxs in your PATH)
  AC_PATH_PROG(APXS_BIN, apxs)
  if test -n "$APXS_BIN"; then
    AC_MSG_RESULT([found ${APXS_BIN}. Use --with-apxs to specify another.])
  fi
fi

if test -z "$APXS_BIN"; then
  AC_MSG_ERROR([**** apxs was not found, DSO compilation will not be available.])
else

  AC_MSG_CHECKING(for Apache module directory)
  AP_LIBEXECDIR=`${APXS_BIN} -q LIBEXECDIR`
  AC_MSG_RESULT($AP_LIBEXECDIR)

  AC_MSG_CHECKING([for Apache include directory])
  AP_INCLUDES="-I`${APXS_BIN} -q INCLUDEDIR`"
  AC_MSG_RESULT($AP_INCLUDES)

  AC_MSG_CHECKING([for apr-config --includes])
  APR_BINDIR=`$APXS_BIN -q APR_BINDIR`
  APR_INCLUDES="`$APR_BINDIR/apr-config --includes`"
  AC_MSG_RESULT($APR_INCLUDES)

  AC_MSG_CHECKING([for apu-config --includes])
  APU_BINDIR=`$APXS_BIN -q APU_BINDIR`
  APU_INCLUDES="`$APU_BINDIR/apu-config --includes`"
  AC_MSG_RESULT($APU_INCLUDES)

  AC_MSG_CHECKING([for CFLAGS from APXS])
  for flag in CFLAGS EXTRA_CFLAGS EXTRA_CPPFLAGS NOTEST_CFLAGS; do
      APXS_CFLAGS="$APXS_CFLAGS `$APXS_BIN -q $flag`"
  done
  AC_MSG_RESULT($APXS_CFLAGS)

  AC_SUBST(AP_LIBEXECDIR)
  AC_SUBST(AP_INCLUDES)
  AC_SUBST(APR_INCLUDES)
  AC_SUBST(APU_INCLUDES)
  AC_SUBST(APXS_CFLAGS)
  AC_SUBST(APXS_BIN)

fi

])

