bin_PROGRAMS = tests/configuration
tests_configuration_LDFLAGS = -ldl -lpthread -L../lib -lrrr
tests_configuration_SOURCES = configuration.c ../global.c ../main.c \
	type_array.c
tests_configuration_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" -DVL_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
TESTS = tests/configuration
