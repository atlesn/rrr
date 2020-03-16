AC_INIT([Read Route Record], 0.16-4)
AC_DEFINE([RRR_CONFIG_VERSION], "0.16-4", [Full version])
AC_DEFINE([RRR_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([RRR_CONFIG_VERSION_MINOR], 16, [Minor version])
AC_DEFINE([RRR_CONFIG_VERSION_REVISION], 4, [Revision number])
AC_DEFINE([RRR_TYPE_MAX_BLOB_LENGTH], 1024, [Maximum size of blob type int type arrays])
#AC_DEFINE([RRR_MYSQL_BIND_MAX], 16, [Maximum number of bind columns for MySQL])
AC_DEFINE([RRR_TMP_PATH], "/tmp", [Temporary directory])
AC_DEFINE([RRR_MESSAGE_MIME_TYPE], "application/rrr-message", [MIME type of RRR message])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_SUBDIRS([src/blockdevlogger])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
#AC_PROG_YACC
#AM_PROG_LEX
AM_SILENT_RULES([yes])

echo "#define RRR_BUILD_TIMESTAMP " `date +%Y%m%d%H%M%S` > build_timestamp.h
echo "#define RRR_BUILD_DIR \""`pwd`"\"" > build_directory.h

AC_CHECK_HEADERS([pthread.h sys/un.h linux/un.h endian.h])
AC_CHECK_FUNCS(vsnprintf vasprintf strcasestr strlcpy)

AC_ARG_WITH([code-coverage], [AS_HELP_STRING([--with-code-coverage], [Enable code coverage compilation])], [enable_codecov=yes], [enable_codecov=no])
# AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable encryption support in network modules])], [enable_encryption=no], [enable_encryption=yes])
AC_ARG_WITH([mysql],[AS_HELP_STRING([--without-mysql],[build without the MySQL bindings])],[enable_mysql=no],[enable_mysql=yes])
AC_ARG_WITH([perl5],[AS_HELP_STRING([--without-perl5],[build without the Perl5 bindings])],[enable_perl5=no],[enable_perl5=yes])
AC_ARG_WITH([usb],[AS_HELP_STRING([--without-usb],[build without the USB bindings])],[enable_usb=no],[enable_usb=yes])
AC_ARG_WITH([python3],[AS_HELP_STRING([--without-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])
AC_ARG_ENABLE([python3-debug],[AS_HELP_STRING([--enable-python3-debug],[build with Python 3 debugging])],[enable_python3_debug=yes],[enable_python3_debug=no])
AC_ARG_ENABLE([perl5-debug],[AS_HELP_STRING([--enable-perl5-debug],[build with Perl5 debugging])],[enable_perl5_debug=yes],[enable_perl5_debug=no])
AC_ARG_ENABLE([gnu-debug],[AS_HELP_STRING([--enable-gnu-debug],[build with debugging of RRR GNU functions; always enable compat functions])],[enable_gnu_debug=yes],[enable_gnu_debug=no])
AC_ARG_VAR([PYTHON3_FORCE_VERSION], [Force a specific python version to be used, e.g. 3.6])

AC_MSG_CHECKING([for RRR GNU Debug])
AS_IF([test "x$enable_gnu_debug" = xno], [
	AC_MSG_RESULT([RRR GNU Debug disabled])
], [
	AC_DEFINE([RRR_WITH_GNU_DEBUG], [1], [Enable RRR GNU Debug (compat functions always enabled)])
	AC_MSG_RESULT([yes])
])

CFLAGS_CODECOV=""
AC_MSG_CHECKING([for code coverage compilation])
AS_IF([test "x$enable_codecov" = xyes], [
	CFLAGS_CODECOV="-ftest-coverage -fprofile-arcs"
	AC_MSG_RESULT([$CFLAGS_CODECOV])
], [
	AC_MSG_RESULT([no])
])
AC_SUBST([CFLAGS_CODECOV])

AM_CFLAGS="$AM_CFLAGS $CFLAGS_CODECOV -include $srcdir/config.h -include $srcdir/build_timestamp.h -Wunreachable-code -Wstrict-prototypes -Wall -Wextra -Wno-clobbered -Werror=implicit-function-declaration"
AC_SUBST(AM_CFLAGS)

AM_CONDITIONAL([RRR_WITH_PERL5], [test "x$enable_perl5" = "xyes"])
AC_MSG_CHECKING([for perl5 enabled])
AS_IF([test "x$enable_perl5" = xno], [
	AC_MSG_RESULT([Not compiling with perl5])
], [
	AC_MSG_RESULT([yes])

	AC_DEFINE([RRR_WITH_PERL5], [1], [Enable perl5 extensions])

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
	perl5_ldflags_auto=`${PERL5_INTERPRETER} -MExtUtils::Embed -e ldopts`
	PERL5_LDFLAGS="$perl5_ldflags_auto"
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

	AC_MSG_CHECKING([Generating Perl5 XSI source])
	perl5_xsi_source="$srcdir/src/lib/perl5_xsi.c"
	${PERL5_INTERPRETER} -MExtUtils::Embed -e xsinit -- -o ${perl5_xsi_source}
	perl5_result=$?

	if test x"${perl5_result}" = x"0"; then
		AC_MSG_RESULT([$perl5_xsi_source])
	else
		AC_MSG_ERROR([Error while generating Perl5 XSI source file, result was "$perl5_result"])
	fi

	AC_SUBST([PERL5_CFLAGS])
	AC_SUBST([PERL5_LDFLAGS])

	AC_SUBST([PERL5_REVISION])
	AC_SUBST([PERL5_VERSION])
	AC_SUBST([PERL5_SUBVERSION])

	AC_SUBST([PERL5_INTERPRETER])
])

AM_CONDITIONAL([RRR_WITH_PYTHON3], [test "x$enable_python3" = "xyes"])
AC_MSG_CHECKING([for python3 enabled])
AS_IF([test "x$enable_python3" = xno], [
	AC_MSG_RESULT([Not compiling with python3])
], [
	AC_MSG_RESULT([yes])

	AC_DEFINE([RRR_WITH_PYTHON3], [1], [Enable python3 extensions])

	python3_version=""

	if test x"${PYTHON3_FORCE_VERSION}" != "x"; then
		python3="python${PYTHON3_FORCE_VERSION}"
		AC_CHECK_PROG(PYTHON3_INTERPRETER,"python${PYTHON3_FORCE_VERSION}",yes)
	else
		for version_tmp in 3.8 3.7; do
			python3_tmp="python$version_tmp"
			AC_CHECK_PROG(PYTHON3_INTERPRETER,${python3_tmp},yes)
			if test x"${PYTHON3_INTERPRETER}" = "xyes"; then
				python3_version=${version_tmp}
				break
			fi
		done
	fi

	python3="python${python3_version}"

	AC_MSG_CHECKING([python version >= 3.7 or forced version])
	if test "x${python3}" = "x"; then
		AC_MSG_ERROR("Supported version of python3 not found")
	fi
	AC_MSG_RESULT([${python3}])

	AC_MSG_CHECKING([for python3 debug enabled])
	if test "x$enable_python3_debug" = x"yes"; then
		python3_config_bin="${python3}-dbg-config"
		AC_MSG_RESULT([$python3_config_bin])
	else
		python3_config_bin="${python3}-config"
		AC_MSG_RESULT([no])
	fi

	python3_libs_from_pkg=""
	python3_cflags_from_pkg=""

	python3_embed_pkg_path="python-$python3_version-embed"

	python3_libs_from_pkg=`pkg-config $python3_embed_pkg_path --silence-errors --libs`
	python3_cflags_from_pkg=`pkg-config $python3_embed_pkg_path --silence-errors --cflags`

	AC_CHECK_PROG(PYTHON3_CONFIG,"$python3_config_bin",yes)
	if test x"${PYTHON3_CONFIG}" = x"yes"; then
		AC_DEFINE([RRR_WITH_PYTHON3], [1], [Build with python3 support], [])
	else
		AC_MSG_ERROR("Could not find python3-config for ${python3}")
	fi

	PYTHON3_CFLAGS=`$python3_config_bin --cflags | sed 's/-O3/ /g' | sed 's/-Wall/ /g'`
	PYTHON3_CFLAGS="${python3_cflags_from_pkg} ${AM_CFLAGS} ${PYTHON3_CFLAGS}"

	PYTHON3_LDFLAGS=`$python3_config_bin --ldflags`
	PYTHON3_LDFLAGS="${PYTHON3_LDFLAGS} $python3_libs_from_pkg"

	echo "Python3 CFLAGS: $PYTHON3_CFLAGS"
	echo "Python3 LDFLAGS: $PYTHON3_LDFLAGS"

	AC_SUBST([PYTHON3_CFLAGS])
	AC_SUBST([PYTHON3_LDFLAGS])

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

AM_CONDITIONAL([RRR_WITH_MYSQL], [test "x$with_mysql" != xno])
AC_MSG_CHECKING([MySQL module inclusion])
AS_IF([test "x$with_mysql" = xno], [
	AC_MSG_RESULT([Not compiling with MySQL module])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_MYSQL], [1], [Compile with MySQL module])
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

AM_COND_IF([RRR_WITH_PERL5], [AC_CONFIG_FILES([src/perl5/xsub/Makefile.PL])])
AM_COND_IF([RRR_WITH_PYTHON3], [AC_CONFIG_FILES([src/python/Makefile])])

AC_CONFIG_FILES(Makefile src/Makefile src/modules/Makefile src/lib/Makefile
				src/tests/Makefile src/tests/modules/Makefile
				misc/Makefile
)
AC_OUTPUT
