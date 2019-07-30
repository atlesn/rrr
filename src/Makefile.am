SUBDIRS = lib modules tests python blockdevlogger perl5 perl5/xsub
bin_PROGRAMS = rrr
rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr
rrr_SOURCES = rrr.c global.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/rrr\""
