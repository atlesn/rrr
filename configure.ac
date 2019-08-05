AC_INIT([Read Route Record], 0.12)
AC_DEFINE([VL_CONFIG_VERSION], 0.12, [Full version])
AC_DEFINE([VL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([VL_CONFIG_VERSION_MINOR], 12, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 16, [Max number of command line arguments])
AC_DEFINE([RRR_TYPE_MAX_DEFINITIONS], 16, [Maximum number of type definitions int type arrays])
AC_DEFINE([RRR_TYPE_MAX_BLOB_LENGTH], 1024, [Maximum size of blob type int type arrays])
AC_DEFINE([RRR_MYSQL_BIND_MAX], 16, [Maximum number of bind columns for MySQL])
AC_DEFINE([RRR_TMP_PATH], "/tmp", [Temporary directory])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_SUBDIRS([src/blockdevlogger])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
#AM_SILENT_RULES([yes])

echo "#define VL_BUILD_TIMESTAMP " `date +%Y%m%d%H%M%S` > build_timestamp.h
echo "#define RRR_BUILD_DIR \""`pwd`"\"" > build_directory.h

AM_CFLAGS="$AM_CFLAGS -include $srcdir/config.h -include $srcdir/build_timestamp.h -Wunreachable-code -Wstrict-prototypes -Wall -Wextra -Wno-clobbered"
AC_SUBST(AM_CFLAGS)

AC_CHECK_HEADERS([pthread.h])

AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable encryption support in network modules])], [enable_encryption=no], [enable_encryption=yes])
AC_ARG_WITH([mysql],[AS_HELP_STRING([--without-mysql],[build without the MySQL bindings])],[enable_mysql=no],[enable_mysql=yes])
AC_ARG_WITH([perl5],[AS_HELP_STRING([--without-perl5],[build without the Perl5 bindings])],[enable_perl5=no],[enable_perl5=yes])
AC_ARG_WITH([usb],[AS_HELP_STRING([--without-usb],[build without the USB bindings])],[enable_usb=no],[enable_usb=yes])
AC_ARG_WITH([python3],[AS_HELP_STRING([--without-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])
AC_ARG_ENABLE([python3-debug],[AS_HELP_STRING([--enable-python3-debug],[build with Python 3 debugging])],[enable_python3_debug=yes],[enable_python3_debug=no])
AC_ARG_ENABLE([perl5-debug],[AS_HELP_STRING([--enable-perl5-debug],[build with Perl5 debugging])],[enable_perl5_debug=yes],[enable_perl5_debug=no])
AC_ARG_VAR([PYTHON3_FORCE_VERSION], [Force a specific python version to be used, e.g. 3.6])

AM_CONDITIONAL([VL_WITH_PERL5], [test "x$enable_perl5" = "xyes"])
AC_MSG_CHECKING([for perl5 enabled])
AS_IF([test "x$enable_perl5" = xno], [
	AC_MSG_RESULT([Not compiling with perl5])
], [
	AC_MSG_RESULT([yes])

	AC_DEFINE([VL_WITH_PERL5], [1], [Enable perl5 extensions])

	if test x"${enable_perl5_debug}" = x"yes"; then
		AC_CHECK_PROG(PERL5_INTERPRETER,debugperl,debugperl)
	else
		AC_CHECK_PROG(PERL5_INTERPRETER,perl,perl)
	fi

	PERL5_REVISION=`perl -MConfig -e 'print "$Config{api_revision}\n"'`
	PERL5_VERSION=`perl -MConfig -e 'print "$Config{api_version}\n"'`
	PERL5_SUBVERSION=`perl -MConfig -e 'print "$Config{api_subversion}\n"'`

	AC_MSG_CHECKING([Perl5 >= 5.026])
	if test x"${PERL5_REVISION}" != "x5"; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR("Perl5 is required but not found");
	fi
	if test ${PERL5_VERSION} -lt 26; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR("Perl 5 version >= 26 is required but not found");
	fi
	AC_MSG_RESULT([yes])

	AC_MSG_CHECKING([Perl5 CFLAGS])
	PERL5_CFLAGS=`${PERL5_INTERPRETER} -MExtUtils::Embed -e ccopts`
	AC_MSG_RESULT([$PERL5_CFLAGS])

	AC_MSG_CHECKING([Perl5 LDFLAGS])
	PERL5_LDFLAGS=`${PERL5_INTERPRETER} -MExtUtils::Embed -e ldopts`
	AC_MSG_RESULT([$PERL5_LDFLAGS])

	AC_MSG_CHECKING([perl5 compilation and linking])
	AC_LANG_CONFTEST([
		AC_LANG_SOURCE([[
			#include <EXTERN.h>
			#include <perl.h>
			int main (int argc, char **argv) {
				PERL_SYS_INIT3(&argc, &argv, NULL);
				PerlInterpreter *interpreter = perl_alloc();
				perl_free(interpreter);
				PERL_SYS_TERM();
				return 0;
			}
		]])
	])

	$CC -o conftest conftest.c ${PERL5_CFLAGS} ${PERL5_LDFLAGS}
	perl5_result=$?
	if test x"${perl5_result}" = x"0"; then
		./conftest
		perl5_result=$?
		if test x"${perl5_result}" = x"0"; then
			AC_MSG_RESULT([OK])
		else
			AC_MSG_ERROR([Test run of perl5 program failed with status "$?"])
		fi
	else
		AC_MSG_ERROR([Test of perl5 compilation failed, make sure libperl-dev is installed.])
	fi

	AC_MSG_CHECKING([Perl5 XSI source])
	perl5_xsi_source="$srcdir/src/lib/perl5_xsi.c"
	${PERL5_INTERPRETER} -MExtUtils::Embed -e xsinit -- -o ${perl5_xsi_source}
	perl5_result=$?

	if test x"${perl5_result}" = x"0"; then
		AC_MSG_RESULT([$perl5_xsi_file])
	else
		AC_MSG_ERROR([Error while generating Perl5 XSI source file, result was "$perl5_result"])
	fi

	enable_perl5_xsi=yes
	AM_CONDITIONAL([VL_WITH_PERL5_XSI], [test "x$enable_perl5_xsi" = "xyes"])

	AC_SUBST([PERL5_CFLAGS])
	AC_SUBST([PERL5_LDFLAGS])

	AC_SUBST([PERL5_REVISION])
	AC_SUBST([PERL5_VERSION])
	AC_SUBST([PERL5_SUBVERSION])

	AC_SUBST([PERL5_INTERPRETER])
])

AM_CONDITIONAL([VL_WITH_PYTHON3], [test "x$enable_python3" = "xyes"])
AC_MSG_CHECKING([for python3 enabled])
AS_IF([test "x$enable_python3" = xno], [
	AC_MSG_RESULT([Not compiling with python3])
], [
	AC_MSG_RESULT([yes])

	AC_DEFINE([VL_WITH_PYTHON3], [1], [Enable python3 extensions])

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
		src/python/Makefile src/perl5/xsub/Makefile.PL misc/Makefile
)
AC_OUTPUT
