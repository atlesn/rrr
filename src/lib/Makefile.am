if VL_WITH_OPENSSL
encryption = crypt.c module_crypt.c
endif

lib_LTLIBRARIES = librrr.la
libvlogger_la_CFLAGS = ${AM_CFLAGS} ${OPENSSL_INCLUDES}
librrr_la_LDFLAGS = -lpthread -ldl ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}
librrr_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c ${encryption} \
ip.c types.c version.c configuration.c settings.c instance_config.c \
module_thread.c instances.c senders.c poll_helper.c modules.c

if VL_WITH_PYTHON3
librrr_la_LIBADD = librrrpython3.la
noinst_LTLIBRARIES = librrrpython3.la
librrrpython3_la_SOURCES = python3.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS}
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS} -fPIC
endif
