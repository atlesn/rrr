SUBDIRS = lib modules
bin_PROGRAMS = vlogger
vlogger_LDFLAGS = -ldl -lpthread -L./lib -lvlogger -lcrypto
vlogger_SOURCES = voltagelogger.c modules.c global.c
vlogger_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/voltagelogger\""
