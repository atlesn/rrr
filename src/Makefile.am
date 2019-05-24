SUBDIRS = lib modules
bin_PROGRAMS = rrr
vlogger_LDFLAGS = -ldl -lpthread -L./lib -lrrr -lcrypto
vlogger_SOURCES = rrr.c modules.c global.c
vlogger_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/voltagelogger\""
