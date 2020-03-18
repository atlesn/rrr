SUBDIRS = lib modules tests python
bin_PROGRAMS = rrr rrr_post
noinst_PROGRAMS = rrr_http_client

rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr
rrr_SOURCES = rrr.c global.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DRRR_MODULE_PATH="\"${libdir}/rrr\""

rrr_post_LDFLAGS = -lrrr -L./lib
rrr_post_SOURCES = rrr_post.c global.c main.c
rrr_post_CFLAGS = ${AM_CFLAGS}

rrr_http_client_LDFLAGS = -lrrr -L./lib
rrr_http_client_SOURCES = rrr_http_client.c global.c main.c
rrr_http_client_CFLAGS = ${AM_CFLAGS}

if RRR_WITH_PERL5
all-local:
	if [ ! -f ${top_srcdir}/src/perl5/xsub/Makefile ]; then	cd ${top_srcdir}/src/perl5/xsub; ${PERL5_INTERPRETER} ./Makefile.PL; fi; cd ${top_srcdir}/src/perl5/xsub; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Making perl xsub"; make
clean-local:
	if [ ! -f ${top_srcdir}/src/perl5/xsub/Makefile ]; then cd ${top_srcdir}/src/perl5/xsub; ${PERL5_INTERPRETER} ./Makefile.PL; fi; cd ${top_srcdir}/src/perl5/xsub; echo "Cleaning perl xsub"; make clean
endif
