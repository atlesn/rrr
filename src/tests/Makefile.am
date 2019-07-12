SUBDIRS = modules 

noinst_PROGRAMS = test
test_LDFLAGS = -ldl -lpthread -L../lib -lrrr
test_SOURCES = test.c ../global.c ../main.c
test_CFLAGS = ${AM_CFLAGS} \
	-DVL_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DVL_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DVL_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
TESTS = test
