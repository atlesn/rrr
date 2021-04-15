AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_MACRO_DIRS([m4])

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

AC_CHECK_HEADERS([rrr/rrr-config.h])

AM_CFLAGS="$AM_CFLAGS $CFLAGS_CODECOV -std=c11 -Wunreachable-code -Wstrict-prototypes -Wall -Wextra -Wno-clobbered -Werror=implicit-function-declaration -D_XOPEN_SOURCE=700"
AM_LDFLAGS=""

AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)

AC_MSG_CHECKING([cmodule installation directory])
CMODULE_DIR=`rrr -i  | grep cmodule-dir | sed 's/cmodule-dir\s*:\s*//'`
AS_IF([test "x$?" != "x0"], [
	AC_MSG_ERROR([Error while running rrr binary. Make sure it can be found in PATH.])
])
AC_MSG_RESULT([$CMODULE_DIR])

AC_DEFINE([CMODULE_DIR], ["${CMODULE_DIR}"], [cmodule installation directory reported by RRR binary])
AC_SUBST([CMODULE_DIR])

AC_CONFIG_FILES(
	Makefile
)

AC_OUTPUT

# Make sure dependency_libs is always set to empty in new .la files to avoid
# recursive depedency linking
echo "rrr: disabling libtool depedency_libs variable"
sed "s/^dependency_libs=.*/dependency_libs=''/" < libtool > libtool.new
mv libtool.new libtool
chmod +x libtool
