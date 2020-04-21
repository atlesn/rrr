SUBDIRS = lib modules tests python
bin_PROGRAMS = rrr rrr_post rrr_stats
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

rrr_stats_LDFLAGS = -lrrr -L./lib
rrr_stats_SOURCES = rrr_stats.c global.c main.c
rrr_stats_CFLAGS = ${AM_CFLAGS}

if RRR_WITH_PERL5
all-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Making perl xsub"; make
install-data-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Making perl xsub"; make install
clean-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Cleaning perl xsub"; make clean
endif
