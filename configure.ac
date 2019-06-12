AC_INIT([Voltage Logger], 0.3)
AC_DEFINE([VL_CONFIG_VERSION], 0.3, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 3, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 32, [Max number of command line arguments])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_CHECK_HEADERS([usb.h pthread.h openssl/crypto.h openssl/evp.h openssl/err.h openssl/sha.h openssl/rand.h mysql/mysql.h])

AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([VL_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([VL_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])

AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h"

AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL

AC_SUBST(AM_CFLAGS)

AC_CONFIG_FILES(Makefile src/Makefile src/modules/Makefile src/lib/Makefile)
AC_OUTPUT
