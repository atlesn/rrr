lib_LTLIBRARIES = librrr.la
librrr_la_LDFLAGS = -lpthread
librrr_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c crypt.c module_crypt.c

if ENABLE_PYTHON3
librrr_la_LIBADD = librrrpython3.la
noinst_LTLIBRARIES = librrrpython3.la
librrrpython3_la_SOURCES = python3.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS}
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS} -fPIC
endif


