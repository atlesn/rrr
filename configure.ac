AC_INIT([Voltage Logger], 0.1)
AC_DEFINE([VL_CONFIG_VERSION], 0.1, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 1, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 16, [Max number of command line arguments])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_WITH([mysql], [AS_HELP_STRING([--without-mysql], [Disable the MySQL module])], [], [with_mysql=yes])
AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable encryption support in network modules])], [], [with_encryption=yes])

AC_CHECK_HEADERS([usb.h pthread.h])

AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([VL_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([VL_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])

AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h"

AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL

AC_SUBST(AM_CFLAGS)

AM_CONDITIONAL([VL_WITH_OPENSSL], [test "x$with_encryption" != xno])
AC_MSG_CHECKING([Checking encryption usage])
AS_IF([test "x$with_encryption" = xno], [
	AC_MSG_RESULT([Not compiling with encryption])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([VL_WITH_OPENSSL], [1], [Enable encryption in network modules])
	AX_CHECK_OPENSSL([], [
		AC_MSG_ERROR([Cannot compile with encrypion, missing OpenSSL])
	])
	AC_CHECK_HEADERS([openssl/crypto.h openssl/evp.h openssl/err.h openssl/sha.h openssl/rand.h])
])

AM_CONDITIONAL([VL_WITH_MYSQL], [test "x$with_mysql" != xno])
AC_MSG_CHECKING([MySQL module inclusion])
AS_IF([test "x$with_mysql" = xno], [
	AC_MSG_RESULT([Not compiling with MySQL module])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([VL_WITH_MYSQL], [1], [Compile with MySQL module])
	AX_LIB_MYSQL([5.0.0])
	AC_CHECK_HEADERS([mysql/mysql.h])
	AC_MSG_CHECKING([integer sizes for MySQL])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <stdint.h>
			#include <stdio.h>
			
			int main (int argc, char *argv[]) {
				FILE *fd = fopen("conftest.out", "w+");
				if (fd == NULL) {
					return 1;
				}
			
				int ret = 0;
				if (sizeof(unsigned long long int) < sizeof(uint64_t)) {
					fprintf (fd, "Error: Size of 'unsigned long long int' is too small to fit 'uint64_t'\n");
					ret = 1;
				}
				if (sizeof(unsigned long int) < sizeof(uint32_t)) {
					fprintf (fd, "Error: Size of 'unsigned long int' is too small to fit 'uint32_t'\n");
					ret = 1;
				}
				fclose(fd);
			
				return ret;
			}
		]])
	], [
		AC_MSG_RESULT([OK])
	], [
		echo "Test returned: `cat conftest.out`";
		AC_MSG_ERROR([Size test of integers failed, cannot compile with MySQL on this system.])
	])
])

AC_CONFIG_FILES(Makefile src/Makefile src/modules/Makefile src/lib/Makefile)
AC_OUTPUT
