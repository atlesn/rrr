SUBDIRS = lib modules tests python
bin_PROGRAMS = rrr rrr_post
noinst_PROGRAMS = rrr_http_client

rrr_LDFLAGS = -ldl -lpthread -L./lib -lrrr
rrr_SOURCES = rrr.c global.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DVL_MODULE_PATH="\"${libdir}/rrr\""

rrr_post_LDFLAGS = -lrrr -L./lib
rrr_post_SOURCES = rrr_post.c global.c main.c
rrr_post_CFLAGS = ${AM_CFLAGS}

rrr_http_client_LDFLAGS = -lrrr -L./lib
rrr_http_client_SOURCES = rrr_http_client.c global.c main.c
rrr_http_client_CFLAGS = ${AM_CFLAGS}

if VL_WITH_PERL5
	perl5_cmd = cd ${top_srcdir}/src/perl5/xsub; ${PERL5_INTERPRETER} ./Makefile.PL
else
	perl5_cmd = true
endif

all-local:
	$(perl5_cmd)
