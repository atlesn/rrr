SUBDIRS = modules 

bin_PROGRAMS = main
main_LDFLAGS = -ldl -lpthread -L../lib -lrrr
main_SOURCES = main.c ../global.c ../main.c
main_CFLAGS = ${AM_CFLAGS} \
	-DVL_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DVL_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DVL_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
TESTS = main
