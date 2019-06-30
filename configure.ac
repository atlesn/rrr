AC_INIT([Read Route Record], 0.5)
AC_DEFINE([VL_CONFIG_VERSION], 0.5, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 5, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 16, [Max number of command line arguments])
AC_DEFINE([RRR_MAX_INSTANCES], 16, [Maximum number og simultaneous instances running])
AC_DEFINE([RRR_TYPE_MAX_DEFINITIONS], 16, [Maximum number of type definitions int type arrays])
AC_DEFINE([RRR_TYPE_MAX_BLOB_LENGTH], 1024, [Maximum size of blob type int type arrays])
AC_DEFINE([RRR_MYSQL_BIND_MAX], 16, [Maximum number of bind columns for MySQL])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_WITH([mysql], [AS_HELP_STRING([--without-mysql], [Disable the MySQL module])], [], [with_mysql=yes])
AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable encryption support in network modules])], [], [with_encryption=yes])

AC_CHECK_HEADERS([usb.h pthread.h])

AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([VL_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([VL_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])

AC_ARG_ENABLE([python3],[AS_HELP_STRING([--disable-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])

AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h -include $srcdir/build_timestamp.h"
AC_SUBST(AM_CFLAGS)

echo -n "checking for python3 enabled... "
AM_CONDITIONAL([ENABLE_PYTHON3], [test "x$enable_python3" == "xyes"])
if test "x$enable_python3" == "xyes"; then
	echo "yes"
	AC_CHECK_PROG(PYTHON3_CONFIG,python3-config,yes)
	if test x"${PYTHON3_CONFIG}" == x"yes"; then
		PYTHON3_CFLAGS="`python3-config --cflags | sed 's/-O3/ /g' | sed 's/-Wall/ /g'` ${AM_CFLAGS}"
		AC_SUBST([PYTHON3_CFLAGS])
		AC_SUBST([PYTHON3_LDFLAGS], `python3-config --ldflags`)
		AC_DEFINE([VL_HAVE_PYTHON3], [1], [Build with python3 support], [])
	else
		AC_MSG_ERROR("Could not find python3-config")
	fi
else
	echo "no"
fi

echo "#define VL_BUILD_TIMESTAMP " `date +%Y%m%d%H%M%S` > build_timestamp.h

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
