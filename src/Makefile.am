SUBDIRS = lib modules
bin_PROGRAMS = rrr
rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr -lcrypto
rrr_SOURCES = rrr.c modules.c global.c instances.c
rrr_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/rrr\""
