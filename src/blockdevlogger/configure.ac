AC_INIT([Block Device Logger], 0.1)
AC_DEFINE([BDL_CONFIG_HEADER_START], "BLOCK DEVICE LOGGER", [The block system starts with this string])
AC_DEFINE([BDL_CONFIG_VERSION], 0.1, [Full version])
AC_DEFINE([BDL_CONFIG_VERSION_MAJOR], 0, [Major version])
AC_DEFINE([BDL_CONFIG_VERSION_MINOR], 1, [Minor version])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARGS], 8, [Maximum number of arguments to a command])
AC_DEFINE([CMD_MAXIMUM_CMDLINE_ARG_SIZE], 4096, [Maximum length of an command line argument])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE
LT_INIT
AC_CONFIG_FILES(Makefile src/Makefile src/lib/Makefile)
AC_PROG_CC_STDC
AC_PROG_CC
AC_PROG_INSTALL
AC_OUTPUT
