AC_INIT([Read Route Record], 0.10)
AC_DEFINE([VL_CONFIG_VERSION], 0.10, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 10, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 16, [Max number of command line arguments])
AC_DEFINE([RRR_TYPE_MAX_DEFINITIONS], 16, [Maximum number of type definitions int type arrays])
AC_DEFINE([RRR_TYPE_MAX_BLOB_LENGTH], 1024, [Maximum size of blob type int type arrays])
AC_DEFINE([RRR_MYSQL_BIND_MAX], 16, [Maximum number of bind columns for MySQL])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_SUBDIRS([src/blockdevlogger])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AM_SILENT_RULES([yes])

echo "#define VL_BUILD_TIMESTAMP " `date +%Y%m%d%H%M%S` > build_timestamp.h
echo "#define RRR_BUILD_DIR \""`pwd`"\"" > build_directory.h


AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h -include $srcdir/build_timestamp.h -Wunreachable-code -Wstrict-prototypes -Wall -Wextra -Wno-clobbered"
AC_SUBST(AM_CFLAGS)

AC_CHECK_HEADERS([pthread.h])

AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable encryption support in network modules])], [enable_encryption=no], [enable_encryption=yes])
AC_ARG_WITH([mysql],[AS_HELP_STRING([--without-mysql],[build without the MySQL bindings])],[enable_mysql=no],[enable_mysql=yes])
AC_ARG_WITH([usb],[AS_HELP_STRING([--without-usb],[build without the USB bindings])],[enable_usb=no],[enable_usb=yes])
AC_ARG_WITH([python3],[AS_HELP_STRING([--without-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])
AC_ARG_ENABLE([python3-debug],[AS_HELP_STRING([--enable-python3-debug],[build with the python debugging])],[enable_python3_debug=yes],[enable_python3_debug=no])
AC_ARG_VAR([PYTHON3_FORCE_VERSION], [Force a specific python version to be used, e.g. 3.6])

AM_CONDITIONAL([VL_WITH_PYTHON3], [test "x$enable_python3" = "xyes"])
AC_MSG_CHECKING([for python3 enabled])
AS_IF([test "x$enable_python3" = xno], [
	AC_MSG_RESULT([Not compiling with python3])
], [
	AC_MSG_RESULT([yes])

	AM_PATH_PYTHON([3.6])
	if test x"${PYTHON3_FORCE_VERSION}" != "x"; then
		 AC_SUBST([PYTHON3_MAJOR_VERSION],[`echo "${PYTHON3_FORCE_VERSION}" | awk -F'[[^0-9]]*' '$0=$1'`])
		 AC_SUBST([PYTHON3_MINOR_VERSION],[`echo "${PYTHON3_FORCE_VERSION}" | awk -F'[[^0-9]]*' '$0=$2'`])
	else
		AC_CHECK_PROG(PYTHON3_INTERPRETER,python3,yes)
		if test x"${PYTHON3_INTERPRETER}" = x"yes"; then
			AC_SUBST([PYTHON3_MAJOR_VERSION],[`python3 --version | awk -F'[[^0-9]]*' '$0=$2'`])
			AC_SUBST([PYTHON3_MINOR_VERSION],[`python3 --version | awk -F'[[^0-9]]*' '$0=$3'`])
		else
			AC_MSG_ERROR("Could not find python3 interpreter")
		fi
	fi

	AC_MSG_CHECKING([for python3 debug enabled])
	if test "x$enable_python3_debug" = x"yes"; then
		python3_config_bin="python${PYTHON3_MAJOR_VERSION}.${PYTHON3_MINOR_VERSION}-dbg-config"
		AC_MSG_RESULT([$python3_config_bin])
	else
		python3_config_bin="python${PYTHON3_MAJOR_VERSION}.${PYTHON3_MINOR_VERSION}-config"
		AC_MSG_RESULT([no])
	fi

	AC_CHECK_PROG(PYTHON3_CONFIG,"$python3_config_bin",yes)
	if test x"${PYTHON3_CONFIG}" = x"yes"; then
		AC_DEFINE([VL_WITH_PYTHON3], [1], [Build with python3 support], [])
	else
		AC_MSG_ERROR("Could not find python3-config for version $PYTHON3_MAJOR_VERSION.$PYTHON3_MINOR_VERSION")
	fi

	PYTHON3_CFLAGS="`$python3_config_bin --cflags | sed 's/-O3/ /g' | sed 's/-Wall/ /g'` ${AM_CFLAGS}"
	AC_SUBST([PYTHON3_CFLAGS])
	AC_SUBST([PYTHON3_LDFLAGS], `$python3_config_bin --ldflags`)

	AC_MSG_CHECKING([python version >= 3.3])
	AC_MSG_RESULT([$PYTHON3_MAJOR_VERSION.$PYTHON3_MINOR_VERSION])
	if test ${PYTHON3_MINOR_VERSION} -lt 3; then
		if test ${PYTHON3_MAJOR_VERSION} != 3; then
			AC_MSG_ERROR([Python3 version >= 3.3 is required])
		fi
	fi

	AC_MSG_CHECKING([python version >= 3.7])
	if test ${PYTHON3_MINOR_VERSION} -lt 7; then
		AC_MSG_RESULT([no])
		AC_DEFINE([RRR_PYTHON_VERSION_LT_3_7], [1], [Python version is 3.6 or earlier], [])
	else
		AC_MSG_RESULT([yes])
		AC_DEFINE([RRR_PYTHON_VERSION_GTEQ_3_7], [1], [Python version is 3.7 or greater], [])
	fi

	chmod +x test_python3.sh
	./test_python3.sh "$python3_config_bin"
	PYTHON3_TEST_RESULT="$?"

	AC_MSG_CHECKING([functional python3 config])
	if test x"$PYTHON3_TEST_RESULT" = x"0"; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		echo -e "Include path is: "
		$python3_config_bin --includes
		AC_MSG_ERROR("Python3 test failed")
	fi
])

AM_CONDITIONAL([VL_WITH_OPENSSL], [test "x$with_encryption" != xno])
AC_MSG_CHECKING([for encryption usage])
AS_IF([test "x$with_encryption" = xno], [
	AC_MSG_RESULT([Not compiling with encryption])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([VL_WITH_OPENSSL], [1], [Enable encryption in network modules])
	AX_CHECK_OPENSSL([], [
		AC_MSG_ERROR([Cannot compile with encrypion, missing OpenSSL])
	])
	AC_CHECK_HEADERS([openssl/crypto.h openssl/evp.h openssl/err.h openssl/sha.h openssl/rand.h])
	AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([VL_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
	AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([VL_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])
])

AM_CONDITIONAL([RRR_WITH_USB], [test "x$with_usb" != xno])
AC_MSG_CHECKING([for USB enabled])
AS_IF([test "x$with_usb" = xno], [
	AC_MSG_RESULT([Not compiling with USB])
], [
	AC_MSG_RESULT([yes])
	AC_CHECK_HEADERS([usb.h])
	AC_CHECK_LIB(usb, usb_init, [], AC_MSG_ERROR([usb_init from libusb not found]))
	AC_CHECK_LIB(usb, usb_find_busses, [], AC_MSG_ERROR([usb_find_busses from libusb not found]))
	AC_CHECK_LIB(usb, usb_find_devices, [], AC_MSG_ERROR([usb_find_devices from libusb not found]))
	AC_MSG_CHECKING([usb.h symbols])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <usb.h>
			
			int main (int argc, char *argv[]) {
				struct usb_config_descriptor a;
				struct usb_device_descriptor b;
				struct usb_device c;
				struct usb_bus d;
				return 0;
			}				
		]])
	], [
		AC_MSG_RESULT([OK])
	], [
		AC_MSG_ERROR([Test of symbols from usb.h failed, make sure libusb-dev or libusb-compat is installed.])
	])
])

AM_CONDITIONAL([VL_WITH_MYSQL], [test "x$with_mysql" != xno])
AC_MSG_CHECKING([MySQL module inclusion])
AS_IF([test "x$with_mysql" = xno], [
	AC_MSG_RESULT([Not compiling with MySQL module])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([VL_WITH_MYSQL], [1], [Compile with MySQL module])
	AX_LIB_MYSQL([5.0.0])
	AC_CHECK_HEADERS([mysql/mysql.h], [], [AC_MSG_ERROR([Headers missing])])
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

AC_CONFIG_FILES(Makefile src/Makefile src/modules/Makefile src/lib/Makefile src/tests/Makefile src/tests/modules/Makefile
		src/python/Makefile misc/Makefile
)
AC_OUTPUT
