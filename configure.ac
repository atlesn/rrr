# Even minor version = development, odd minor version = stable
AC_INIT([Read Route Record],[1.29-1])
AC_DEFINE([RRR_CONFIG_VERSION], "1.29-1", [Full version])
AC_DEFINE([RRR_CONFIG_VERSION_MAJOR], 1, [Major version])
AC_DEFINE([RRR_CONFIG_VERSION_MINOR], 29, [Minor version])
AC_DEFINE([RRR_CONFIG_VERSION_REVISION], 1, [Revision number])
AC_DEFINE([RRR_TYPE_MAX_BLOB_LENGTH], 1024, [Maximum size of blob type in type arrays])
#AC_DEFINE([RRR_MYSQL_BIND_MAX], 16, [Maximum number of bind columns for MySQL])
AC_DEFINE([RRR_TMP_PATH], "/tmp", [Temporary directory])
AC_DEFINE([RRR_MESSAGE_MIME_TYPE], "application/rrr-message", [MIME type of RRR message])
AC_DEFINE([RRR_STATS_SOCKET_PREFIX], "rrr_stats", [Socket name prefix for RRR stats socket])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

#AC_CONFIG_SUBDIRS([])

INET_CHECKS()

dnl OpenBSD check for egcc
AC_CHECK_PROG([EGCC], egcc, egcc)
AC_MSG_CHECKING([for OpenBSD EGCC])
AS_IF([test "x${EGCC}" != "x"], [
		AS_IF([test "x${CC}" != "x" ], [
		AC_MSG_RESULT([found, but CC was already set to something (else)])
	], [
		CC=${EGCC}
		AC_MSG_RESULT([${EGCC}])
	])
], [
	AC_MSG_RESULT([no])
])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LT_INIT
AC_PROG_CC
AC_PROG_INSTALL
#AC_PROG_YACC
#AM_PROG_LEX
AM_SILENT_RULES([yes])

echo "#define RRR_BUILD_TIMESTAMP " `date +%Y%m%d%H%M%S` > build_timestamp.h
echo "#define RRR_BUILD_DIR \""`pwd`"\"" > build_directory.h

AC_CHECK_HEADERS([pthread.h sys/un.h linux/un.h endian.h])
AC_CHECK_FUNCS(vsnprintf vasprintf strcasestr strlcpy)

AC_ARG_WITH([encryption], [AS_HELP_STRING([--without-encryption], [Disable LibreSSL/OpenSSL password encryption])], [enable_encryption=no], [enable_encryption=yes])
AC_ARG_WITH([autossl], [AS_HELP_STRING([--without-autossl], [Disable automatic LibreSSL/OpenSSL support])], [enable_auto_ssl=no], [enable_auto_ssl=yes])
AC_ARG_WITH([libressl], [AS_HELP_STRING([--with-libressl], [Force enable LibreSSL support])], [enable_libressl=yes; enable_auto_ssl=no], [ enable_libressl=no ])
AC_ARG_WITH([openssl-ish], [AS_HELP_STRING([--with-openssl-ish], [Force enable OpenSSL (or LibreSSL-style OpenSSL) support])], [enable_openssl=yes; enable_auto_ssl=no], [ enable_openssl=no ])
AC_ARG_WITH([jsonc],[AS_HELP_STRING([--without-jsonc],[build without the json-c bindings])],[enable_jsonc=no],[enable_jsonc=yes])
AC_ARG_WITH([zlib],[AS_HELP_STRING([--without-zlib],[build without the zlib bindings])],[enable_zlib=no],[enable_zlib=yes])
AC_ARG_WITH([nghttp2],[AS_HELP_STRING([--without-nghttp2],[build without the NGHTTP2 bindings])],[enable_nghttp2=no],[enable_nghttp2=yes])
AC_ARG_WITH([mysql],[AS_HELP_STRING([--without-mysql],[build without the MySQL bindings])],[enable_mysql=no],[enable_mysql=yes])
AC_ARG_WITH([perl5],[AS_HELP_STRING([--without-perl5],[build without the Perl5 bindings])],[enable_perl5=no],[enable_perl5=yes])
AC_ARG_WITH([lua],[AS_HELP_STRING([--without-lua],[build without the Lua bindings])],[enable_lua=no],[enable_lua=yes])
AC_ARG_WITH([usb],[AS_HELP_STRING([--with-usb],[build with USB bindings])],[enable_usb=yes],[enable_usb=no])
AC_ARG_WITH([python3],[AS_HELP_STRING([--without-python3],[build without the python bindings])],[enable_python3=no],[enable_python3=yes])
AC_ARG_WITH([runit],[AS_HELP_STRING([--with-runit],[build with the runit bindings])],[enable_runit=yes],[enable_runit=no])
AC_ARG_WITH([openrc],[AS_HELP_STRING([--with-openrc],[build with the OpenRC bindings])],[enable_openrc=yes],[enable_openrc=no])
AC_ARG_WITH([confdir],[AS_HELP_STRING([--without-confdir],[do not install /etc/rrr.conf.d/])],[enable_confdir=no],[enable_confdir=yes])
AC_ARG_WITH([jemalloc],[AS_HELP_STRING([--with-jemalloc],[build with jemalloc support])],[enable_jemalloc=yes],[enable_jemalloc=no])
AC_ARG_WITH([v8],[AS_HELP_STRING([--with-v8],[set root directory for the V8 bindings in where the out/ directory exists])],[],[with_v8=yes])
AC_ARG_ENABLE([python3-debug],[AS_HELP_STRING([--enable-python3-debug],[build with Python 3 debugging])],[enable_python3_debug=yes],[enable_python3_debug=no])
AC_ARG_ENABLE([perl5-debug],[AS_HELP_STRING([--enable-perl5-debug],[build with Perl5 debugging])],[enable_perl5_debug=yes],[enable_perl5_debug=no])
AC_ARG_ENABLE([gnu-debug],[AS_HELP_STRING([--enable-gnu-debug],[build with debugging of RRR GNU functions; always enable compat functions])],[enable_gnu_debug=yes],[enable_gnu_debug=no])
AC_ARG_ENABLE([database-testing],[AS_HELP_STRING([--enable-database-testing],[enable checks requiring custom setup of databases])],[enable_database_testing=yes],[enable_database_testing=no])
AC_ARG_ENABLE([printf-logging], [AS_HELP_STRING([--enable-printf-logging],[use plain printf calls in all log messages. All messages will be printed regardless of debuglevel. Most useful to make compiler validate the log calls.])],[enable_printf_logging=yes],[enable_printf_logging=no])
AC_ARG_ENABLE([v8-sandbox], [AS_HELP_STRING([--enable-v8-sandbox],[Enable V8 sandboxing, this must be done if the installed V8 library has sandboxing enabled.])],[enable_v8_sandbox=yes],[enable_v8_sandbox=no])
AC_ARG_VAR([PYTHON3_FORCE_VERSION], [Force a specific python version to be used, e.g. 3.6])

dnl Disable SystemD for BSD
enable_systemd=no
AC_MSG_CHECKING([for SystemD disabled on BSD])
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for JavaScript enabled])
if test "x$with_v8" != xno; then
	enable_js=yes
	AC_MSG_RESULT([yes])
else
	enable_js=no
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([for RRR GNU Debug])
AS_IF([test "x$enable_gnu_debug" = xno], [
	AC_MSG_RESULT([RRR GNU Debug disabled])
], [
	AC_DEFINE([RRR_WITH_GNU_DEBUG], [1], [Enable RRR GNU Debug (compat functions always enabled)])
	AC_MSG_RESULT([yes])
])

AC_MSG_CHECKING([for development environment compiler warnings])
AS_IF([ test -f ".development" ], [
	RRR_EXTRA_WARNINGS="-Wconversion"
	AC_MSG_RESULT([$RRR_EXTRA_WARNINGS])
], [
	RRR_EXTRA_WARNINGS=""
	AC_MSG_RESULT([none])
])

CFLAGS_CONFIG="-include $srcdir/config.h -include $srcdir/build_timestamp.h"
CFLAGS_COMMON="-include $srcdir/src/lib/intercept.h -Wunreachable-code -Wextra -D_XOPEN_SOURCE=700 -g"
CPPFLAGS="-I/usr/local/include -I/usr/include"
LDFLAGS="-L/usr/local/lib -L/usr/lib -L/lib"
AM_CFLAGS="$AM_CFLAGS -std=c11 $CFLAGS_CONFIG $CFLAGS_COMMON -Wall -Wstrict-prototypes -Werror=implicit-function-declaration -O2"
AM_LDFLAGS=""

AC_MSG_CHECKING([for AM_CFLAGS])
AC_MSG_RESULT([$AM_CFLAGS])
CFLAGS=""

AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)

AC_MSG_CHECKING([for C++ usage])
if test "x$enable_js" != xno; then # autotools complains when using AC_PROG_CXX inside AS_IF
	AC_MSG_RESULT([yes])
	AC_PROG_CXX
	# Dont't use. Sometimes adds gnu17 standard.
	# AX_CXX_COMPILE_STDCXX_17
	AC_DEFINE([RRR_WITH_CXX], [1], [Enable C++])
	AC_LANG_PUSH([C++])
	AC_CHECK_HEADERS([iostream], [], AC_MSG_ERROR([Standard C++ library headers not found]))
	AC_LANG_POP([C++])
	FREEBSD_CXXFLAGS="-DRRR_INTERCEPT_ALLOW_FORK"
	CLANG_CXXFLAGS="-Wno-unused-parameter"
	AM_CXXFLAGS="$AM_CXXFLAGS -std=c++17 $CFLAGS_CONFIG $CFLAGS_COMMON -O3 $CXXFLAGS $FREEBSD_CXXFLAGS $CLANG_CXXFLAGS"
	TEST_CXXFLAGS="-std=c++17 $CFLAGS_COMMON -O3"
	AC_MSG_CHECKING([for AM_CXXFLAGS])
	AC_MSG_RESULT([$AM_CXXFLAGS])
	CXXFLAGS=""
	enable_cxx=yes
else
	AC_MSG_RESULT([no])
	enable_cxx=no
fi

AC_SUBST(AM_CXXFLAGS)

SHELL_VARS_INIT([variables.sh])

SHELL_VARS_EXPORT([RRR_WITH_SYSTEMD], $enable_systemd)
SHELL_VARS_EXPORT([RRR_WITH_PYTHON3], $enable_python3)
SHELL_VARS_EXPORT([RRR_WITH_PERL5], $enable_perl5)
SHELL_VARS_EXPORT([RRR_WITH_LUA], $enable_lua)
SHELL_VARS_EXPORT([RRR_WITH_NGHTTP2], $enable_nghttp2)
SHELL_VARS_EXPORT([RRR_WITH_MYSQL], $enable_mysql)
SHELL_VARS_EXPORT([RRR_WITH_JS], $enable_js)

SHELL_VARS_OUTPUT

AM_CONDITIONAL([RRR_WITH_CXX], [test "x$enable_cxx" != xno])
AM_CONDITIONAL([RRR_WITH_OPENRC], [test "x$enable_openrc" != xno])
AM_CONDITIONAL([RRR_WITH_RUNIT], [test "x$enable_runit" != xno])
AM_CONDITIONAL([RRR_WITH_CONFDIR], [test "x$enable_confdir" != xno])
AM_CONDITIONAL([RRR_WITH_JEMALLOC], [test "x$enable_jemalloc" != xno])
AM_CONDITIONAL([RRR_WITH_JS], [test "x$enable_js" != xno])
AM_CONDITIONAL([RRR_WITH_SYSTEMD], [test "x$enable_systemd" != xno])
AM_CONDITIONAL([RRR_WITH_USB], [test "x$enable_usb" != xno])
AM_CONDITIONAL([RRR_WITH_PYTHON3], [test "x$enable_python3" != xno])
AM_CONDITIONAL([RRR_WITH_PERL5], [test "x$enable_perl5" != xno])
AM_CONDITIONAL([RRR_WITH_LUA], [test "x$enable_lua" != xno])
AM_CONDITIONAL([RRR_WITH_JSONC], [test "x$enable_jsonc" != xno])
AM_CONDITIONAL([RRR_WITH_ZLIB], [test "x$enable_zlib" != xno])
AM_CONDITIONAL([RRR_WITH_NGHTTP2], [test "x$enable_nghttp2" != xno])
AM_CONDITIONAL([RRR_WITH_MYSQL], [test "x$enable_mysql" != xno])

AC_CHECK_LIB(rt, shm_open, [ LIBRT_LIBADD="-lrt" ], [ LIBRT_LIBADD="" ])
AC_SUBST([LIBRT_LIBADD])

AC_CHECK_HEADER([linux/input.h], [have_linux_input=yes], [have_linux_input=no])
AM_CONDITIONAL([RRR_WITH_LINUX_INPUT], [test "x$have_linux_input" != xno])

AC_CHECK_HEADER([dev/evdev/input.h], [have_freebsd_input=yes], [have_freebsd_input=no])
AM_CONDITIONAL([RRR_WITH_FREEBSD_INPUT], [test "x$have_freebsd_input" != xno])

AC_MSG_CHECKING([for Linux-style input device headers])
AS_IF([test "x$have_linux_input" = xno], [
	AC_MSG_RESULT([no])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_LINUX_INPUT], [1], [Enable Linux-style input device control])
])

AC_MSG_CHECKING([for FreeBSD-style input device headers])
AS_IF([test "x$have_freebsd_input" = xno], [
	AC_MSG_RESULT([no])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_FREEBSD_INPUT], [1], [Enable FreeBSD-style input device control])
])

AC_MSG_CHECKING([for libbsd])

have_setproctitle=no
LIBBSD_LIBS=""

# Check for setproctitle. Should be in unistd.h on both BSD and Linux,
# but on linux it's in the libbsd library while on BSD it's in libc.
AC_CHECK_LIB([bsd], [setproctitle], [
	LIBBSD_LIBS="-lbsd"
	have_setproctitle=yes
	AC_DEFINE([RRR_HAVE_LIBBSD], [1], [Have libbsd])
], [])
AC_CHECK_LIB([c], [setproctitle], [
	have_setproctitle=yes
], [])

AS_IF([test "x$have_setproctitle" != xno], [
	AC_DEFINE([RRR_HAVE_SETPROCTITLE], [1], [Have setproctitle])
])

AC_SUBST([LIBBSD_LIBS])
AM_CONDITIONAL([RRR_HAVE_LIBBSD], ["x$LIBBSD_LIBS" != "x"])

AC_CHECK_LIB([bsd], [setproctitle_init], [
	AC_DEFINE([RRR_HAVE_SETPROCTITLE_INIT], [1], [Have setproctitle_init])
], [])

# Check for pthread name setter
AC_MSG_CHECKING([for pthread_setname_np])
AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
		#include <pthread.h>
		#include <stdio.h>
		
		int main (int argc, char *argv[]) {
			pthread_t tid = pthread_self();
			pthread_setname_np(tid, "test");
			return 0;
		}
	]])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_HAVE_PTHREAD_SETNAME_NP], [1], [Have pthread_setname_np])
], [
	AC_MSG_RESULT([no])
])

# Check for limits
AC_MSG_CHECKING([location of limits.h with PATH_MAX])
AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
		#include <linux/limits.h>
		#include <stdio.h>
		
		int main (int argc, char *argv[]) {
			printf("path_max: %i\n", PATH_MAX);
			return 0;
		}
	]])
], [
	AC_MSG_RESULT([linux/limits.h])
	AC_DEFINE([RRR_HAS_PATH_MAX_IN_LINUX_LIMITS_H], [1], [Use linux/limits.h to find PATH_MAX])
], [
	AC_MSG_RESULT([limits.h])
])

AC_MSG_CHECKING([precense of gettid()])
AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
		#define _GNU_SOURCE
		#include <unistd.h>
		#include <sys/types.h>

		int main (int argc, char *argv[]) {
			pid_t tid = gettid();
			return 0;
		}
	]])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_HAVE_GETTID], [1], [Linux-specific gettid() is present])
], [
	AC_MSG_RESULT([no])
])

AC_CHECK_HEADERS([event2/event.h event2/thread.h], [], [AC_MSG_ERROR([libevent headers not found])])
AC_CHECK_LIB([event], [event_base_new], [], [AC_MSG_ERROR([libevent library not found])])
AC_CHECK_LIB([event_pthreads], [evthread_use_pthreads], [], [AC_MSG_ERROR([libevent pthreads library not found])])

AC_SUBST([TLS_CFLAGS])
AC_SUBST([TLS_LDFLAGS])
AC_SUBST([TLS_LIBADD])

TLS_CFLAGS=
TLS_LDFLAGS=
TLS_LIBADD=

CHECK_LIBRESSL_LIBTLS

AC_MSG_CHECKING([for automatic LibreSSL/OpenSSL selection])
AS_IF([test "x$enable_auto_ssl" != xno], [
	AC_MSG_RESULT([yes])
	AS_IF([test "x$HAVE_LIBRESSL_LIBTLS" != "x"],[ enable_libressl=yes ])
	AC_CHECK_HEADERS([openssl/err.h], [ enable_openssl=yes ], [])
], [
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for LibreSSL usage])
AS_IF([test "x$enable_libressl" = xyes], [
	AC_MSG_RESULT([yes])
	AS_IF([test "x$HAVE_LIBRESSL_LIBTLS" = "x"],[
		AC_MSG_ERROR([LibreSSL usage requested but libtls was not found])
	])
	AC_DEFINE([RRR_WITH_LIBRESSL], [1], [Enable encryption in network modules with LibreSSL])

	AC_MSG_CHECKING([LibreSSL CFLAGS])
	AC_MSG_RESULT([$LIBRESSL_LIBTLS_CFLAGS])

	AC_MSG_CHECKING([LibreSSL LDFLAGS])
	AC_MSG_RESULT([$LIBRESSL_LIBTLS_LDFLAGS])

	AC_MSG_CHECKING([LibreSSL LIBADD])
	AC_MSG_RESULT([$LIBRESSL_LIBTLS_LIBADD])

	TLS_CFLAGS=$LIBRESSL_LIBTLS_CFLAGS
	TLS_LDFLAGS=$LIBRESSL_LIBTLS_LDFLAGS
	TLS_LIBADD=$LIBRESSL_LIBTLS_LIBADD
], [
	AC_MSG_RESULT([Not compiling with LibreSSL])
])

AC_MSG_CHECKING([for LibreSSL overrides OpenSSL])
AS_IF([test "x$enable_auto_ssl" != "xno" && test "x$enable_openssl" = "xyes" && test "x$enable_libressl" = "xyes" ], [
	AC_MSG_RESULT([yes])
	enable_openssl=no
], [
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for OpenSSL usage])
AS_IF([test "x$enable_openssl" = xyes], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_OPENSSL], [1], [Enable encryption in network modules with OpenSSL])
	AX_CHECK_OPENSSL([], [
		AC_MSG_ERROR([Cannot compile with encryption, OpenSSL missing])
	])
	AC_CHECK_HEADERS([openssl/crypto.h openssl/evp.h openssl/err.h openssl/sha.h openssl/rand.h])
# Only version >=1.1 supported
#	AC_CHECK_LIB(crypto, CRYPTO_get_new_dynlockid, [AC_DEFINE([RRR_HAVE_OLD_OPENSSL_LOCK], [1], [Have old style lock])], [])
	AC_CHECK_LIB(crypto, CRYPTO_THREAD_lock_new, [AC_DEFINE([RRR_HAVE_NEW_OPENSSL_LOCK], [1], [Have new style thread lock])], [])
	AC_CHECK_LIB(ssl, SSL_get1_peer_certificate, [AC_DEFINE([RRR_HAVE_GET1_PEER_CERTIFICATE], [1], [Have get peer certificate with and without reference incrementing])], [])
	OPENSSL_CFLAGS_COMPAT="-DOPENSSL_API_COMPAT=0x10100000L"
	AC_SUBST([OPENSSL_CFLAGS_COMPAT])
	AC_DEFINE([OPENSSL_API_COMPAT], [0x10100000L], "Use OpenSSL version >= 1.1.0")

	AC_SUBST([TLS_CFLAGS])
	AC_SUBST([TLS_LDFLAGS])
	AC_SUBST([TLS_LIBADD])
], [
	AC_MSG_RESULT([Not compiling with OpenSSL])
])

AC_MSG_CHECKING([only one SSL/TLS library was chosen])
AS_IF([test "x$enable_openssl" = xyes && test "x$enable_libressl" = xyes ], [
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([cannot use both OpenSSL and LibreSSL at the same time, make sure auto-selection is not disabled])
], [
	AC_MSG_RESULT([yes])
])

AC_MSG_CHECKING([for LibreSSL/OpenSSL common cryptography functions])
AS_IF([test "x$enable_encryption" != "xno" ], [
	AC_MSG_RESULT([yes])
	AC_CHECK_HEADERS([openssl/crypto.h openssl/evp.h openssl/sha.h openssl/rand.h])
	AC_DEFINE([RRR_WITH_OPENSSL_CRYPT], [1], "Use OpenSSL/LibreSSL cryptography functions")
	AS_IF([test "x$TLS_LDFLAGS" = "x"], [
		AX_CHECK_OPENSSL([], [
			AC_MSG_ERROR([Cannot compile with encryption, OpenSSL/LibreSSL missing])
		])
		TLS_CFLAGS=$OPENSSL_INCLUDES
		TLS_LDFLAGS=$OPENSSL_LDFLAGS
		TLS_LIBADD=$OPENSSL_LIBS
	])
], [
	AC_MSG_RESULT([not enabled])
])

AC_SUBST([TLS_CFLAGS])
AC_SUBST([TLS_LDFLAGS])
AC_SUBST([TLS_LIBADD])

SHELL_VARS_EXPORT([RRR_WITH_OPENSSL], $enable_openssl)
SHELL_VARS_EXPORT([RRR_WITH_LIBRESSL], $enable_libressl)
SHELL_VARS_EXPORT([RRR_WITH_AUTO_SSL], $enable_auto_ssl)

AM_CONDITIONAL([RRR_WITH_OPENSSL], [test "x$enable_openssl" != xno])
AM_CONDITIONAL([RRR_WITH_OPENSSL_CRYPT], [test "x$enable_encryption" != xno])
AM_CONDITIONAL([RRR_WITH_LIBRESSL], [test "x$enable_libressl" != xno])
AM_CONDITIONAL([RRR_WITH_AUTO_SSL], [test "x$enable_auto_ssl" != xno])

# Make sure jemalloc-test does not include any libraries
LIBS=""

AC_MSG_CHECKING([for jemalloc usage])
AS_IF([test "x$enable_jemalloc" != xno], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_JEMALLOC], [1], [Enable jemalloc allocation])
	AC_CHECK_HEADERS([jemalloc/jemalloc.h], [], AC_MSG_ERROR([jemalloc/jemalloc.h not found]))
	AC_CHECK_LIB(jemalloc, mallocx, [], AC_MSG_ERROR([mallocx from libjemalloc not found]))
	JEMALLOC_LIBS=-ljemalloc
], [
	AC_MSG_RESULT([no])
])

AC_SUBST([JEMALLOC_LIBS])

AC_DEFUN([V8COMPILE], [
	cxx_flags="$TEST_CXXFLAGS $JS_CXXFLAGS $FREEBSD_CXXFLAGS -w"
	ld_flags="$AM_LDFLAGS $JS_LDFLAGS $JS_LIBS"
	$CXX $cxx_flags -o conftest.o -c conftest.cpp && $CXX $cxx_flags conftest.o -o conftest $ld_flags > /dev/null 2>&1 && ./conftest
	if test "$?" = 0; then
		AC_MSG_RESULT([present])
		m4_default([$1], [])
	else
		AC_MSG_RESULT([not present])
		m4_default([$2], [AC_MSG_ERROR([Failed: $CXX $cxx_flags -o conftest.o -c conftest.cpp && $CXX $cxx_flags conftest.o -o conftest $ld_flags && ./conftest])])
	fi
])

AC_DEFUN([V8TESTS],[
	AC_MSG_CHECKING([V8 sandboxing enabled])
	AS_IF([test "x$enable_v8_sandbox" = xyes],[
		AC_MSG_RESULT([yes])
		AC_DEFINE([V8_ENABLE_SANDBOX], [1], [Use sandboxing in V8, this parameter must match with of the V8 library on the system was compiled])
	],[
		AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([V8 compilation and linking without pointer compression V8_COMPRESS_POINTERS])
	AS_IF([test "x$enable_v8_sandbox" = xyes],[
		AC_LANG_CONFTEST([
			AC_LANG_SOURCE([[
				#define V8_ENABLE_SANDBOX 1
				#include <v8.h>
				#include <libplatform/libplatform.h>
				int main (int argc, char **argv) {
					std::unique_ptr<v8::Platform> platform(v8::platform::NewDefaultPlatform());
					v8::V8::InitializeICUDefaultLocation(argv[0]);
					v8::V8::InitializeExternalStartupData(argv[0]);
					v8::V8::InitializePlatform(platform.get());
					v8::V8::Initialize();
					return 0;
				}
			]])
		])
	],[
		AC_LANG_CONFTEST([
			AC_LANG_SOURCE([[
				#include <v8.h>
				#include <libplatform/libplatform.h>
				int main (int argc, char **argv) {
					std::unique_ptr<v8::Platform> platform(v8::platform::NewDefaultPlatform());
					v8::V8::InitializeICUDefaultLocation(argv[0]);
					v8::V8::InitializeExternalStartupData(argv[0]);
					v8::V8::InitializePlatform(platform.get());
					v8::V8::Initialize();
					return 0;
				}
			]])
		])
	])

	V8COMPILE([
		AC_MSG_RESULT([V8 was not built with pointer compression])
		AS_IF([test "x$enable_v8_sandbox" != xno],[
			AC_MSG_RESULT("Note: Specified --enable-v8-sandbox was ignored")

		])
	],[
		AC_MSG_RESULT([V8 was maybe built with pointer compression])

		AC_MSG_CHECKING([V8 compilation and linking with pointer compression])

		AS_IF([test "x$enable_v8_sandbox" = xyes],[
			AC_DEFINE([V8_ENABLE_SANDBOX], [1], [Use sandboxing in V8, this parameter must match with of the V8 library on the system was compiled])
			AC_LANG_CONFTEST([
				AC_LANG_SOURCE([[
					#define V8_COMPRESS_POINTERS 1
					#define V8_ENABLE_SANDBOX 1
					#include <v8.h>
					#include <libplatform/libplatform.h>
					int main (int argc, char **argv) {
						std::unique_ptr<v8::Platform> platform(v8::platform::NewDefaultPlatform());
						v8::V8::InitializeICUDefaultLocation(argv[0]);
						v8::V8::InitializeExternalStartupData(argv[0]);
						v8::V8::InitializePlatform(platform.get());
						v8::V8::Initialize();
						return 0;
					}
				]])
			])
		],[
			AC_LANG_CONFTEST([
				AC_LANG_SOURCE([[
					#define V8_COMPRESS_POINTERS 1
					#include <v8.h>
					#include <libplatform/libplatform.h>
					int main (int argc, char **argv) {
						std::unique_ptr<v8::Platform> platform(v8::platform::NewDefaultPlatform());
						v8::V8::InitializeICUDefaultLocation(argv[0]);
						v8::V8::InitializeExternalStartupData(argv[0]);
						v8::V8::InitializePlatform(platform.get());
						v8::V8::Initialize();
						return 0;
					}
				]])
			])
		])
		V8COMPILE

		AC_MSG_RESULT([V8 was built with pointer compression])
		AC_DEFINE([V8_COMPRESS_POINTERS], [1], [Use compressed pointers in V8, this parameter must match with of the V8 library on the system was compiled])
	])

	AC_MSG_CHECKING([V8 has BackingStore])
	AC_LANG_CONFTEST([
		AC_LANG_SOURCE([[
			#include <v8.h>
			int main (int argc, char **argv) {
				auto size = sizeof(v8::BackingStore);
				return sizeof(v8::BackingStore) == 0;
			}
		]])
	])
	V8COMPILE([
		AC_DEFINE([RRR_HAVE_V8_BACKINGSTORE], [1], [Have BackingStore for ArrayBuffer])
	],[
		# Not found, no action required
	])

	AC_MSG_CHECKING([V8 has FixedArray arg in ResolveModuleCallback])
	AC_LANG_CONFTEST([
		AC_LANG_SOURCE([[
			#include <v8.h>
			#include <v8-script.h>
			v8::MaybeLocal<v8::Module> dummy (
					v8::Local<v8::Context>,
					v8::Local<v8::String>,
					v8::Local<v8::FixedArray>,
					v8::Local<v8::Module>
			) {
				auto ctx = v8::Local<v8::Context>();
				auto mod = v8::Local<v8::Module>();
				mod->InstantiateModule(ctx, dummy);
			}
			int main (int argc, char **argv) {
				return 0;
			}
		]])
	])
	V8COMPILE([
		AC_DEFINE([RRR_HAVE_V8_FIXEDARRAY_IN_RESOLVEMODULECALLBACK], [1], [Have FixedArray in ResolveModuleCallback])
	],[
		# Not found, no action required
	])

	AC_MSG_CHECKING([V8 has primitive arguments to ScriptOrigin])
	AC_LANG_CONFTEST([
		AC_LANG_SOURCE([[
			#include <v8.h>
			#include <v8-message.h>
			int main (int argc, char **argv) {
				auto dummy = v8::ScriptOrigin(
						nullptr,
						v8::Local<v8::Value>(),
						0,
						0,
						false,
						-1,
						v8::Local<v8::Value>(),
						false,
						false,
						false
				);
				return 0;
			}
		]])
	])
	V8COMPILE([
		AC_DEFINE([RRR_HAVE_V8_PRIMITIVE_ARGS_TO_SCRIPTORIGIN], [1], [Have primitive arguments to ScriptOrigin])
	],[
		# Not found, no action required
	])
])

AC_LANG_PUSH([C++])

AC_MSG_CHECKING([for V8 usage])
AS_IF([test "x$enable_js" != xno],[
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_JS], [1], [Enable V8])

	pkgconfig_ok=no
	if test "x$with_v8" = xyes; then
		# Note: May return OK but empty string, this is OK
		v8_cflags=`pkg-config --cflags --silence-errors v8 v8_libbase v8_libplatform`
		if test $? -ne 0; then
			v8_include_dir_test="/usr/local/include /usr/include"
		else
			pkgconfig_ok=yes
		fi
	else
		v8_include_dir_test="$with_v8/include"
	fi

	AC_MSG_CHECKING([for V8 include directories])

	if test "x$pkgconfig_ok" = xyes; then
		if test "x$v8_cflags" = x; then
			AC_MSG_RESULT([empty])
		else
			AC_MSG_RESULT([$v8_cflags])
		fi
	else
		if test "x$v8_cflags" = x; then
			for dir in $v8_include_dir_test; do
				if test -d $dir; then
					v8_cflags="$v8_cflags -I$dir"
				fi
			done
		fi

		if test "x$v8_cflags" != x; then
			AC_MSG_RESULT([$v8_cflags])
		else
			AC_MSG_ERROR("not found")
		fi
	fi

	AC_MSG_CHECKING([for V8 libraries])

	pkgconfig_ok=no
	if test "x$with_v8" != x; then
		v8_ldflags=`pkg-config --libs-only-L --silence-errors v8 v8_libbase v8_libplatform`
		v8_libs=`pkg-config --libs-only-l --silence-errors v8 v8_libbase v8_libplatform`
		if test $? -ne 0; then
			v8_lib_dir_test="/usr/local/lib /usr/lib"
			v8_libs="-lv8 -licuuc -licui18n -licudata -lv8_libbase -lv8_libplatform"
		else
			pkgconfig_ok=yes
		fi
	else
		v8_lib_dir_test=`ls $with_v8/out/*`
		v8_libs="-lv8 -licuuc -licui18n -licudata -lv8_libbase"
	fi

	if test "x$v8_libs" != x; then
		AC_MSG_RESULT([$v8_libs])
	else
		AC_MSG_ERROR("not found")
	fi

	AC_MSG_CHECKING([for V8 library directories])

	if test "x$pkgconfig_ok" = xyes; then
		if test "x$v8_ldlags" = x; then
			AC_MSG_RESULT([empty])
		else
			AC_MSG_RESULT([$v8_ldlags])
		fi
	else
		if test "x$v8_lib_dir_test" != x; then
			v8_ldflags=""
			for dir in $v8_lib_dir_test; do
				if test -d $dir; then
					v8_ldflags="$v8_ldflags -L$dir"
				fi
			done
		fi

		if test "x$v8_ldflags" != x; then
			AC_MSG_RESULT([$v8_ldflags])
		else
			AC_MSG_ERROR("not found")
		fi
	fi

	JS_CXXFLAGS="$v8_cflags -DRRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT -DV8_DEPRECATION_WARNINGS"
	JS_LDFLAGS="$v8_ldflags"
	JS_LIBS="$v8_libs"

	V8TESTS
],[
	AC_MSG_RESULT([no])
])

AC_SUBST([JS_CXXFLAGS])
AC_SUBST([JS_LDFLAGS])
AC_SUBST([JS_LIBS])

AC_LANG_POP([C++])

# Make sure Perl-test does not include any libraries
LIBS=""

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
		AC_MSG_ERROR("Perl5 is required but not found")
	fi
	if test ${PERL5_VERSION} -lt 26; then
		AC_MSG_RESULT([no])
		AC_MSG_ERROR("Perl 5 version >= 26 is required but not found");
	fi
	AC_MSG_RESULT([yes])

	# Remove -specs=/... causing -pie to get inserted on RH-systems

	AC_MSG_CHECKING([Perl5 CFLAGS])
	PERL5_CFLAGS=$(${PERL5_INTERPRETER} -MExtUtils::Embed -e ccopts | ${PERL5_INTERPRETER} -E 'while(<STDIN>){s/\s*-specs\S*//g;print;}')
	if test "$CXX" = "c++"; then
		PERL5_CFLAGS="$PERL5_CFLAGS -Wno-compound-token-split-by-macro"
	fi

	AC_MSG_RESULT([$PERL5_CFLAGS])

	AC_MSG_CHECKING([Perl5 LDFLAGS])
	perl5_ldflags_auto=$(${PERL5_INTERPRETER} -MExtUtils::Embed -e ldopts | ${PERL5_INTERPRETER} -E 'while(<STDIN>){s/\s*-specs\S*//g;print;}')
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

	# Need -O to avoid warning about FORTIFY_SOURCE
	$CC -o conftest conftest.c ${PERL5_CFLAGS} -O3 ${PERL5_LDFLAGS}
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

# Make sure Lua-test does not include any libraries
LIBS=""

AC_MSG_CHECKING([for lua enabled])
AS_IF([test "x$enable_lua" = xno], [
	AC_MSG_RESULT([Not compiling with lua])
], [
	AC_MSG_RESULT([yes])

	AC_DEFINE([RRR_WITH_LUA], [1], [Enable lua extensions])

	have_lua_h_set=no

	header_version=""
	lib_version=""

	for version in lua lua5.4 lua-5.4 lua5.3 lua-5.3; do
		LUA_CFLAGS=`pkg-config --cflags $version --silence-errors`
		LUA_LDFLAGS=`pkg-config --libs $version --silence-errors`

		AC_MSG_CHECKING([for pkgconfig-given Lua libraries and headers with version $version])

		# Note: Sometimes pkg-config returns good result for libs but not for cflags

		if test "x${LUA_CFLAGS}" != "x"; then
			header_version=`echo $version | sed -e 's/lua-//' | sed -e 's/lua//'`
		fi

		if test "x${LUA_LDFLAGS}" != "x"; then
			AC_MSG_RESULT([yes])
			lib_version=`echo $version | sed -e 's/lua-//' | sed -e 's/lua//'`
			break
		else
			AC_MSG_RESULT([no])
			LUA_CFLAGS=""
			LUA_LDFLAGS=""
		fi
	done

	AC_MSG_CHECKING([for pkgconfig-given Lua libraries but not headers])
	if test "x${LUA_LDFLAGS}" != "x" -a "x${LUA_CFLAGS}" = "x"; then
		# LDFLAGS is given by pkg-config, but not CFLAGS. This might
		# indicate that headers are not in includes subdirectory.
		if echo "x${LUA_LDFLAGS}" | grep -qE '\-llua(\s|$)'; then
			AC_MSG_RESULT([possibly, must check for headers and symbols])
			AC_CHECK_HEADERS([lua.h], [ LUA_CFLAGS=" " have_lua_h_set=yes ])
			if test "x${LUA_CFLAGS}" = "x"; then
				# Headers without version number not found
				LUA_LDFLAGS=""
			else
				# Have versionless library and headers without version number
				# and headers are not in subdirectory.
				AC_CHECK_LIB([lua], [lua_close], [ ], [
				      LUA_LDFLAGS=""
				      LUA_CFLAGS=""
				])
			fi
		else
			# Library is not versionless, check for specific supported versions
			AC_MSG_RESULT([no])
		fi
	else
		AC_MSG_RESULT([no])
	fi

	if test "x${LUA_CFLAGS}" = "x"; then
		# AC_CHECK_HEADERS produces warning "you should use literals"
		# when used with variables. Work around this by checking paths
		# manually.
		for base in /usr/local/include /usr/local; do
			for version in lua5.4 lua-5.4 lua5.3 lua-5.3; do
				AC_MSG_CHECKING([for lua.h in ${base}/${version}])
				if test -f "${base}/${version}/lua.h"; then
					header_version=`echo $version | sed -e 's/lua-//' | sed -e 's/lua//'`
					LUA_CFLAGS="-I${base}/${version}"
					AC_MSG_RESULT([yes])
				else
					AC_MSG_RESULT([no])
				fi

				if test "x${LUA_CFLAGS}" != "x"; then
					break
				fi
			done
			if test "x${LUA_CFLAGS}" != "x"; then
				break
			fi
		done
	fi

	if test "x{$LUA_LDFLAGS}" = "x"; then
		# Don't use loop as that causes warning "you should use literals"
		AC_CHECK_LIB([lua5.4], [lua_close], [ LUA_LDFLAGS="-llua5.4" lib_version="5.4" ])
		if test "x{$LUA_LDFLAGS}" = "x"; then
			AC_CHECK_LIB([lua-5.4], [lua_close], [ LUA_LDFLAGS="-llua-5.4" lib_version="5.4" ])
		fi
		if test "x{$LUA_LDFLAGS}" = "x"; then
			AC_CHECK_LIB([lua5.3], [lua_close], [ LUA_LDFLAGS="-llua5.3" lib_version="5.3" ])
		fi
		if test "x{$LUA_LDFLAGS}" = "x"; then
			AC_CHECK_LIB([lua-5.3], [lua_close], [ LUA_LDFLAGS="-llua-5.3" lib_version="5.3" ])
		fi
		exit 1
	fi

	AC_MSG_CHECKING([for lua header/lib version mismatch])
	if test "x${header_version}" != "x" -a "x${lib_version}" != "x"; then
		if test "x${header_version}" != "x${lib_version}"; then
			AC_MSG_RESULT(['${header_version}' '${lib_version}' => yes])
			AC_MSG_ERROR([Lua header and library version mismatch, header is ${header_version} but library is ${lib_version}])
		else
			AC_MSG_RESULT(['${header_version}' '${lib_version}' => no])
		fi
	else
		AC_MSG_RESULT(['${header_version}' '${lib_version}' => no])
	fi

	AC_MSG_CHECKING([for lua CFLAGS])
	AS_IF([ test "x${LUA_CFLAGS}" = "x" ],[
		AC_MSG_ERROR([Could not find Lua headers])
	],[
		AC_MSG_RESULT([${LUA_CFLAGS}])
	])

	AC_MSG_CHECKING([for lua LDFLAGS])
	AS_IF([ test "x${LUA_LDFLAGS}" = "x" ],[
		AC_MSG_ERROR([Could not find Lua libraries])
	],[
		AC_MSG_RESULT([${LUA_LDFLAGS}])
	])

	AS_IF([test "$have_lua_h_set" != "yes" ], [
		AC_DEFINE([HAVE_LUA_H], [1], [Have lua.h in either include path set in CFLAGS or in root include directory])
	])

	AC_SUBST([LUA_CFLAGS])
	AC_SUBST([LUA_LDFLAGS])

	AC_MSG_CHECKING([for lua integer size])

	CFLAGS="${LUA_CFLAGS}"
	AC_RUN_IFELSE([
		AC_LANG_PROGRAM([[
			#if defined(HAVE_LUA5_4_LUA_H)
			#  include <lua5.4/lua.h>
			#elif defined(HAVE_LUA5_3_LUA_H)
			#  include <lua5.3/lua.h>
			#elif defined(HAVE_LUA_H)
			#  include <lua.h>
			#else
			#  error "No HAVE_LUA defined"
			#endif
		]],[[
			#if LUA_MAXINTEGER == LLONG_MAX
			return 12
			#elif LUA_MAXINTEGER == LONG_MAX
			return 11
			#elif LUA_MAXINTEGER == INT_MAX
			return 10
			#else
			#  error "Could not determing lua integer size"
			#endif
		]])
	], [
		AC_MSG_ERROR([test did not return non-zero result])
	], [
		RES=$?
		AS_IF([test $RES -eq 12], [
			AC_MSG_RESULT([long long int])
			AC_DEFINE([RRR_LUA_INTTYPE],[long long int],[Type for Lua integers])
			AC_DEFINE([RRR_LUA_INTTYPE_PRI],[lli],[Printf format for Lua integers])
		], [test $RES -eq 11], [
			AC_MSG_RESULT([long int])
			AC_DEFINE([RRR_LUA_INTTYPE],[long int],[Type for Lua integers])
			AC_DEFINE([RRR_LUA_INTTYPE_PRI],[li],[Printf format for Lua integers])
		], [test $RES -eq 10], [
			AC_MSG_RESULT([int])
			AC_DEFINE([RRR_LUA_INTTYPE],[int],[Type for Lua integers])
			AC_DEFINE([RRR_LUA_INTTYPE_PRI],[i],[Printf format for Lua integers])
		], [
			AC_MSG_ERROR([Unexpected return value ${RES}]);
		])
	])
	CFLAGS=""
])

# Make sure Python-test does not include any libraries
LIBS=""

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
		for version_tmp in 3.12 3.11 3.10 3.9 3.8 3.7; do
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
	PYTHON3_CFLAGS="${python3_cflags_from_pkg} ${PYTHON3_CFLAGS}"

	PYTHON3_LDFLAGS=`$python3_config_bin --ldflags`
	PYTHON3_LDFLAGS="${PYTHON3_LDFLAGS} $python3_libs_from_pkg"

	echo "Python3 CFLAGS: $PYTHON3_CFLAGS"
	echo "Python3 LDFLAGS: $PYTHON3_LDFLAGS"

	AC_SUBST([PYTHON3_CFLAGS])
	AC_SUBST([PYTHON3_LDFLAGS])

	chmod +x test_python3.sh
	./test_python3.sh "$CC" "$python3_config_bin"
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
	
	AC_MSG_CHECKING([PyTypeObject tp_print member])
	cflags_orig="$CFLAGS"
	CFLAGS="$PYTHON3_CFLAGS"
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <Python.h>
			
			int main (int argc, char *argv[]) {
				PyTypeObject o;
	    		o.tp_print = NULL;
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([RRR_PYTHON3_HAS_PTYPEOBJECT_TP_PRINT], [1], [Python3 PyTypeObject has .tp_print member (version <= 3.8)])
	], [
		AC_MSG_RESULT([no])
	])
	CFLAGS="$cflags_orig"
])

AC_MSG_CHECKING([for USB enabled])
AS_IF([test "x$enable_usb" = xno], [
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

# Make sure json-c-test does not include any libraries
LIBS=""

AC_MSG_CHECKING([json-c bindings])
AS_IF([test "x$enable_jsonc" = xno], [
	AC_MSG_RESULT([Not compiling with json-c bindings])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_JSONC], [1], [Compile with json-c bindings])
	AC_CHECK_HEADERS([json-c/json_tokener.h json-c/json_object.h json-c/json_object_iterator.h json-c/json_util.h])
	AC_CHECK_LIB(json-c, json_tokener_new, [], AC_MSG_ERROR([json_tokener_new from json-c not found]))

	AC_CHECK_LIB(json-c, json_object_new_null, [
		AC_DEFINE([RRR_HAVE_JSONC_NEW_NULL], [1], [We have json-c json_object_new_null])
	], [])

	AC_CHECK_LIB(json-c, json_object_new_uint64, [
		AC_DEFINE([RRR_HAVE_JSONC_NEW_UINT64], [1], [We have json-c json_object_new_uint64])
	], [])

	AC_MSG_CHECKING([json_object_object_add is of void type])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <json-c/json_object.h>
			int main (int argc, char *argv[]) {
				json_object *obj1 = json_object_new_object();
				json_object *obj2 = json_object_new_object();
				// Compilation fails if function is of void type
				return json_object_object_add(obj1, "key", obj2);
			}
		]])
	], [
		AC_MSG_RESULT([no])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([RRR_HAVE_JSONC_OBJECT_ADD_VOID], [1], [json_object_object_add is of void type])
	])

	JSONC_CFLAGS=""
	JSONC_LDFLAGS=""
	JSONC_LIBS="-ljson-c"

	AC_SUBST([JSONC_CFLAGS])
	AC_SUBST([JSONC_LDFLAGS])
	AC_SUBST([JSONC_LIBS])
])

AC_MSG_CHECKING([zlib bindings])
AS_IF([test "x$enable_zlib" = xno], [
	AC_MSG_RESULT([Not compiling with zlib bindings])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_ZLIB], [1], [Compile with zlib bindings])
	AC_CHECK_HEADERS([zlib.h])
	AC_CHECK_LIB(z, inflate, [], AC_MSG_ERROR([inflate from zlib not found]))
	AC_CHECK_LIB(z, deflate, [], AC_MSG_ERROR([deflate from zlib not found]))

	ZLIB_CFLAGS=""
	ZLIB_LDFLAGS="-lz"

	AC_SUBST([ZLIB_CFLAGS])
	AC_SUBST([ZLIB_LDFLAGS])
])

AC_MSG_CHECKING([NGHTTP2 bindings])
AS_IF([test "x$enable_nghttp2" = xno], [
	AC_MSG_RESULT([Not compiling with NGHTTP2 bindings])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_NGHTTP2], [1], [Compile with NGHTTP2 bindings])
	AC_CHECK_HEADERS([nghttp2/nghttp2.h])
	AC_CHECK_LIB(nghttp2, nghttp2_pack_settings_payload, [], AC_MSG_ERROR([nghttp2_pack_settings_payload from nghttp2 not found]))
	NGHTTP2_CFLAGS=""
	NGHTTP2_LDFLAGS="-lnghttp2"

	AC_SUBST([NGHTTP2_CFLAGS])
	AC_SUBST([NGHTTP2_LDFLAGS])
	AC_SUBST([NGHTTP2_LIBS])
])

# Make sure MySQL-test does not include any libraries
LIBS=""

AC_MSG_CHECKING([MySQL module inclusion])
AS_IF([test "x$enable_mysql" = xno], [
	AC_MSG_RESULT([Not compiling with MySQL module])
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_WITH_MYSQL], [1], [Compile with MySQL module])
	AX_LIB_MYSQL([5.0.0])
	AC_MSG_CHECKING([headers for MariaDB/MySQL])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <mysql/mysql.h>
			
			int main (int argc, char *argv[]) {
				return 0;
			}
		]])
	], [
		AC_MSG_RESULT([OK])
	], [
		AC_MSG_ERROR([MariaDB/MySQL header mysql/mysql.h not found])
	])
	AC_MSG_CHECKING([integer sizes for MariaDB/MySQL])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <mysql/mysql.h>
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

AC_MSG_CHECKING([enabled database testing])
AS_IF([test "x$enable_database_testing" = xyes], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_ENABLE_DB_TESTING], [1], [Enable database testing in test suite])
],[
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([enabled printf logging])
AS_IF([test "x$enable_printf_logging" = xyes], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([RRR_ENABLE_PRINTF_LOGGING], [1], [Enable printf logging for all log messages])
],[
	AC_MSG_RESULT([no])
])

AC_DEFUN([REQUIRE_CONFDIR], [
	if [test "x$enable_confdir" != "xyes"]; then
		AC_MSG_ERROR([confdir was not enabled, but is required])
	fi
])

AC_MSG_CHECKING([for RRR environment file directory])
RRR_ENVIRONMENT_FILE_DIR="${sysconfdir}"
AC_MSG_RESULT([${sysconfdir}])
AC_SUBST(RRR_ENVIRONMENT_FILE_DIR)

AC_MSG_CHECKING([for RRR config file directory])
RRR_CONF_DIR="${sysconfdir}/rrr.conf.d"
AC_MSG_RESULT([${sysconfdir}/rrr.conf.d])
AC_SUBST(RRR_CONF_DIR)

AC_MSG_CHECKING([for confdir usage])
AC_CONFIG_FILES([misc/confdir/Makefile])
AS_IF([test "x$enable_confdir" = xyes], [
	AC_MSG_RESULT([yes, ${RRR_CONF_DIR}])
],[
	AC_MSG_RESULT([no])
])

AM_CONDITIONAL([RRR_SYSTEMD_NO_UNIT_INSTALL], [test "x$RRR_SYSTEMD_NO_UNIT_INSTALL" = "x1"])
AM_CONDITIONAL([RRR_SYSTEMD_NO_TMPFILES_INSTALL], [test "x$RRR_SYSTEMD_NO_TMPFILES_INSTALL" = "x1"])

AC_MSG_CHECKING([for systemd usage])
AC_CONFIG_FILES([misc/systemd/Makefile])
AS_IF([test "x$enable_systemd" = xyes], [
	REQUIRE_CONFDIR
	SYSTEMD_INIT

	AC_MSG_RESULT([yes]);

	AC_SUBST([RRR_SYSTEMD_UNIT_DIR], [SYSTEMD_SYSTEM_UNIT_DIR])
	AC_MSG_CHECKING([For systemd unit directory])
	AC_MSG_RESULT([SYSTEMD_SYSTEM_UNIT_DIR])

	AC_SUBST([RRR_TMPFILES_DIR], [SYSTEMD_TMPFILES_DIR])
	AC_MSG_CHECKING([For systemd tmpfiles.d directory])
	AC_MSG_RESULT([SYSTEMD_TMPFILES_DIR])

	AC_CONFIG_FILES([misc/systemd/make-service.sh])
	AC_CONFIG_FILES([misc/systemd/make-tmpfiles.sh])

	AC_MSG_CHECKING([for systemd service file no installation command])
	AS_IF([test "x$RRR_SYSTEMD_NO_INSTALL" = "x1"] , [
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

	AC_CHECK_HEADER([systemd/sd-journal.h], [], AC_MSG_ERROR([missing SystemD development headers]))
	AC_CHECK_LIB(systemd, sd_journal_print, [], AC_MSG_ERROR([sd_journal_print from libsystemd]))

	AC_DEFINE([HAVE_JOURNALD], [1], [Have native SystemD/journald logging])

	JOURNALD_LIBS="-lsystemd"
	AC_SUBST([JOURNALD_LIBS])

	RRR_RUN_DIR="/run/rrr"
],[
	RRR_RUN_DIR="/tmp"
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for RRR run directory])
AC_MSG_RESULT([${RRR_RUN_DIR}])
AC_SUBST(RRR_RUN_DIR)
AC_DEFINE_UNQUOTED([RRR_RUN_DIR], ["${RRR_RUN_DIR}"], [Default run directory for sockets])

AC_MSG_CHECKING([for RRR data directory])
RRR_DATA_DIR="${localstatedir}/lib/rrr"
AC_MSG_RESULT([${RRR_DATA_DIR}])
AC_SUBST(RRR_DATA_DIR)

AC_CONFIG_FILES([src/make-paths.sh])

AC_MSG_CHECKING([for daemon username])
AS_IF([test "x$RRR_DAEMON_USERNAME" != "x"] , [
	AC_MSG_RESULT([${RRR_DAEMON_USERNAME}])
], [
	RRR_DAEMON_USERNAME=daemon
	AC_MSG_RESULT([${RRR_DAEMON_USERNAME} (by default)])
])
AC_SUBST(RRR_DAEMON_USERNAME)

AC_MSG_CHECKING([for runit usage])
AC_CONFIG_FILES([misc/runit/Makefile])
AS_IF([test "x$enable_runit" = xyes], [
	REQUIRE_CONFDIR
	AC_SUBST([RUNIT_SV_DIR], [/etc/sv/rrr/])
	AC_CONFIG_FILES([misc/runit/make-runit.sh])
	AC_MSG_RESULT([yes, sv directory is ${RUNIT_SV_DIR}])
],[
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for openrc usage])
AC_CONFIG_FILES([misc/openrc/Makefile])
AS_IF([test "x$enable_openrc" = xyes], [
	REQUIRE_CONFDIR
	AC_CONFIG_FILES([misc/openrc/make-service.sh])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

MODULE_DIR="\${exec_prefix}/lib/rrr"
AC_MSG_CHECKING([module installation directory])
AC_MSG_RESULT([${MODULE_DIR}])

CMODULE_DIR="\${exec_prefix}/lib/rrr/cmodules"
AC_MSG_CHECKING([cmodule installation directory])
AC_MSG_RESULT([${CMODULE_DIR}])

AC_SUBST([MODULE_DIR])
AC_SUBST([CMODULE_DIR])

# Clear all automatically added libs. Library users must specify
# libraries locally in Makefile.am
LIBS=""

AM_COND_IF([RRR_WITH_PERL5], [AC_CONFIG_FILES([src/perl5/xsub/Makefile.PL])])
AM_COND_IF([RRR_WITH_PYTHON3], [AC_CONFIG_FILES([src/python/Makefile])])

AC_CONFIG_FILES([src/tests/test.sh],[chmod +x src/tests/test.sh])
AC_CONFIG_FILES([src/test.sh],[chmod +x src/test.sh])

AC_CONFIG_FILES(
	Makefile
	src/Makefile
	src/modules/Makefile
	src/lib/Makefile
	src/tests/Makefile
	src/tests/lib/Makefile
	src/tests/modules/Makefile
	misc/Makefile
	src/cmodules/Makefile
)

AC_OUTPUT
SHELL_VARS_CLEANUP

# Make sure dependency_libs is always set to empty in new .la files to avoid
# recursive depedency linking
echo "rrr: disabling libtool depedency_libs variable"
sed "s/^dependency_libs=.*/dependency_libs=''/" < libtool > libtool.new
mv libtool.new libtool
chmod +x libtool

# Copy config.h file for installation together with other headers
cp -f config.h src/lib/rrr-build-config.h
