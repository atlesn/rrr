AM_CFLAGS = @AM_CFLAGS@ -Wextra

lib_LTLIBRARIES = configuration.la

module_ldflags=-module -avoid-version -shared -L../../lib -lrrr

configuration_la_LDFLAGS = ${module_ldflags}
configuration_la_CFLAGS = ${AM_CFLAGS} \
	-DVL_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DVL_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DVL_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
configuration_la_SOURCES = configuration.c type_array.c