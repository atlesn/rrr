AC_INIT([Read Route Record], 0.5)
AC_DEFINE([VL_CONFIG_VERSION], 0.5, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 5, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 16, [Max number of command line arguments])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_CHECK_HEADERS([usb.h pthread.h openssl/crypto.h openssl/evp.h openssl/err.h openssl/sha.h openssl/rand.h mysql/mysql.h])

AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([VL_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([VL_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])

AC_ARG_ENABLE([python3],[AS_HELP_STRING([--disable-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])

echo -n "Checking for python3 enabled... "
AM_CONDITIONAL([ENABLE_PYTHON3], [test "x$enable_python3" == "xyes"])
if test "x$enable_python3" == "xyes"; then
	echo "yes"
	AC_CHECK_PROG(PYTHON3_CONFIG,python3-config,yes)
	if test x"${PYTHON3_CONFIG}" == x"yes"; then
		AC_SUBST([PYTHON3_CFLAGS], `python3-config --cflags`)
		AC_SUBST([PYTHON3_LDLAGS], `python3-config --ldflags`)
		AC_DEFINE([VL_HAVE_PYTHON3], [1], [Build with python3 support], [])
	else
		AC_MSG_ERROR("Could not find python3-config")
	fi
else
	echo "no"
fi


AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h"

AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL

AC_SUBST(AM_CFLAGS)

AC_CONFIG_FILES(Makefile src/Makefile src/modules/Makefile src/lib/Makefile)
AC_OUTPUT
