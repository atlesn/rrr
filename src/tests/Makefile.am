bin_PROGRAMS = tests/configuration
tests_configuration_LDFLAGS = -ldl -lpthread -L../lib -lrrr
tests_configuration_SOURCES = configuration.c ../global.c
tests_configuration_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"$(top_srcdir)/src/modules/.libs\""
TESTS = tests/configuration
