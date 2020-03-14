SUBDIRS = modules 

# if RRR_WITH_PYTHON3
# isolated_python_SOURCES = isolated_python.c ../global.c
# isolated_python_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\" \
#	-DRRR_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" -O0
# isolated_python_LDFLAGS = ${PYTHON3_LDFLAGS} -ldl -lpthread -L../lib -lrrr -O0
# python = isolated_python
# endif

noinst_PROGRAMS = test ${python}
test_LDFLAGS = -ldl -lpthread -lm -L../lib -lrrr -O0 ${PYTHON3_LDFLAGS} ${PERL5_LDFLAGS}
test_SOURCES = test.c ../global.c ../main.c
test_CFLAGS = ${AM_CFLAGS} -O0 \
	-DRRR_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DRRR_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DRRR_TEST_PATH="\"$(abs_top_builddir)/src/tests\""
TESTS = test
