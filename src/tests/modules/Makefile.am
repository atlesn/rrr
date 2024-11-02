AM_CFLAGS = @AM_CFLAGS@ -Wextra

check_LTLIBRARIES = test_module.la

if RRR_WITH_MYSQL
mysql_include = -lrrrmysql
endif

module_ldflags=-module -avoid-version -shared -L../../lib/.libs -lrrr $(mysql_include)

test_module_la_LDFLAGS = ${module_ldflags} -rpath /nowhere
test_module_la_CFLAGS = ${AM_CFLAGS} \
	-DVL_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DVL_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DVL_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
test_module_la_SOURCES = test_module.c type_array.c
