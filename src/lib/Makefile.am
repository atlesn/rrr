if VL_WITH_OPENSSL
encryption = crypt.c module_crypt.c
endif

lib_LTLIBRARIES = libvlogger.la
libvlogger_la_CFLAGS = ${AM_CFLAGS} ${OPENSSL_INCLUDES}
libvlogger_la_LDFLAGS = -lpthread ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}
libvlogger_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c ${encryption}
