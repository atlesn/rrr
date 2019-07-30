SUBDIRS = lib modules tests python blockdevlogger 
bin_PROGRAMS = rrr
rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr
rrr_SOURCES = rrr.c global.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/rrr\""

all-local:
	cd ${top_srcdir}/src/perl5/xsub; ${PERL5_INTERPRETER} ./Makefile.PL
