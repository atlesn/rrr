SUBDIRS = modules

#if RRR_WITH_PYTHON3
#isolated_python_SOURCES = isolated_python.c ../global.c
#isolated_python_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\" \
#	-DRRR_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" -O0
#isolated_python_LDFLAGS = ${PYTHON3_LDFLAGS} -ldl -lpthread -L../lib -lrrr -O0
#python = isolated_python
#endif

if RRR_WITH_JSONC
test_jsonc = test_json.c
endif

noinst_PROGRAMS = test make_test_data send_ip send_fifo sha1/sha sha1/shatest sha256/shatest ${python}

test_LDFLAGS = ${PYTHON3_LDFLAGS} ${PERL5_LDFLAGS}
test_LDADD = -ldl -lpthread -lm -L../lib/.libs -lrrr ${jsonc_libadd}
test_SOURCES = test.c \
	../main.c \
	test_usleep.c \
	test_msleep_signal_safe.c \
	test_fixp.c \
	test_inet.c \
	test_condition.c \
	${test_jsonc} \
	test_conversion.c \
	test_msgdb.c \
	test_nullsafe.c \
	test_allocator.c \
	test_mmap_channel.c \
	test_increment.c
test_CFLAGS = ${AM_CFLAGS} -O0 -fPIE -DPIE \
	-DRRR_MODULE_PATH="\"$(top_builddir)/src/modules/.libs\"" \
	-DRRR_TEST_MODULE_PATH="\"$(top_builddir)/src/tests/modules/.libs\"" \
	-DRRR_TEST_PATH="\"$(abs_top_builddir)/src/tests\"" \
	-fprofile-arcs -ftest-coverage

make_test_data_SOURCES = make_test_data.c ../lib/messages/msg_checksum.c ../lib/util/crc32.c ../lib/util/rrr_endian.c
make_test_data_CFLAGS = -fPIE -DPIE

send_ip_SOURCES = send_ip.c
send_ip_CFLAGS = ${AM_CFLAGS} -DRRR_INTERCEPT_ALLOW_STRERROR -fPIE -DPIE

send_fifo_SOURCES = send_fifo.c
send_fifo_CFLAGS = ${AM_CFLAGS}
send_fifo_LDFLAGS = -L../lib -lrrr ${PERL5_LDFLAGS} -fPIE -DPIE

sha1_sha_SOURCES = sha1/sha.c
sha1_sha_LDFLAGS = -L../lib -lrrr ${PERL5_LDFLAGS} -fPIE -DPIE

sha1_shatest_SOURCES = sha1/shatest.c
sha1_shatest_LDFLAGS = -L../lib -lrrr ${PERL5_LDFLAGS} -fPIE -DPIE

sha256_shatest_SOURCES = sha256/shatest.c
sha256_shatest_LDFLAGS = -L../lib -lrrr ${PERL5_LDFLAGS} -fPIE -DPIE

TESTS = test.sh test_passwd.sh sha1/shatest sha256/shatest
