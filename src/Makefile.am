SUBDIRS = lib modules tests python cmodules
bin_PROGRAMS = rrr rrr_post rrr_stats rrr_passwd rrr_auth
noinst_PROGRAMS = rrr_http_client rrr_http_server

# We must include Perl5 rpath when linking the binaries
if RRR_WITH_PERL5
perl5_ldflags=$(PERL5_LDFLAGS)
endif

rrr_SOURCES = rrr.c global.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DRRR_MODULE_PATH="\"${libdir}/rrr\"" -DRRR_MODULE_PATH="\"${libdir}/rrr/cmodules/\"" -DRRR_INTERCEPT_ALLOW_WAITPID
rrr_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_post_SOURCES = rrr_post.c global.c main.c
rrr_post_CFLAGS = ${AM_CFLAGS}
rrr_post_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_passwd_SOURCES = rrr_passwd.c global.c main.c
rrr_passwd_CFLAGS = ${AM_CFLAGS}
rrr_passwd_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_auth_SOURCES = rrr_auth.c global.c main.c
rrr_auth_CFLAGS = ${AM_CFLAGS}
rrr_auth_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_http_client_SOURCES = rrr_http_client.c global.c main.c
rrr_http_client_CFLAGS = ${AM_CFLAGS}
rrr_http_client_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_http_server_SOURCES = rrr_http_server.c global.c main.c
rrr_http_server_CFLAGS = ${AM_CFLAGS}
rrr_http_server_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

rrr_stats_SOURCES = rrr_stats.c global.c main.c
rrr_stats_CFLAGS = ${AM_CFLAGS}
rrr_stats_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags}

if RRR_WITH_PERL5
all-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Making perl xsub"; make
install-data-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Making perl xsub"; make install
clean-local:
	echo "Generating Perl Makefile"; cd ${top_srcdir}/src/perl5/xsub; rm -f Makefile; ${PERL5_INTERPRETER} ./Makefile.PL; echo "Cleaning perl xsub"; make clean
endif
