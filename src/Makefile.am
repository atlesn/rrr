SUBDIRS = lib modules tests
bin_PROGRAMS = rrr
rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr
rrr_SOURCES = rrr.c global.c
rrr_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/rrr\""
