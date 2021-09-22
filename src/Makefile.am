SUBDIRS = lib modules tests python cmodules
bin_PROGRAMS = rrr rrr_post rrr_stats rrr_passwd rrr_auth rrr_msg
noinst_PROGRAMS = rrr_http_client rrr_http_server rrr_msgdb
TESTS = test.sh

datadir = @RRR_DATA_DIR@

# We must include Perl5 rpath when linking the binaries
if RRR_WITH_PERL5
perl5_ldflags=$(PERL5_LDFLAGS)
endif

# Binaries must be built with -fPIE to match the library, as some
# functionallity require functions to have the same addresses in both
# programs and library. By using -fPIE, function addresses will only be
# resolved at run-time in the executables.

rrr_SOURCES = rrr.c main.c
rrr_CFLAGS = ${AM_CFLAGS} -DRRR_MODULE_PATH="\"@MODULE_DIR@\"" -DRRR_CMODULE_PATH="\"@CMODULE_DIR@\"" -DRRR_INTERCEPT_ALLOW_WAITPID -fpie
rrr_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_post_SOURCES = rrr_post.c main.c
rrr_post_CFLAGS = ${AM_CFLAGS} -fpie
rrr_post_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_passwd_SOURCES = rrr_passwd.c main.c
rrr_passwd_CFLAGS = ${AM_CFLAGS} -fpie
rrr_passwd_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_auth_SOURCES = rrr_auth.c main.c
rrr_auth_CFLAGS = ${AM_CFLAGS} -fpie
rrr_auth_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_http_client_SOURCES = rrr_http_client.c main.c
rrr_http_client_CFLAGS = ${AM_CFLAGS} -fpie
rrr_http_client_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie
rrr_http_client_LDADD = -levent

rrr_http_server_SOURCES = rrr_http_server.c main.c
rrr_http_server_CFLAGS = ${AM_CFLAGS} -fpie
rrr_http_server_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_stats_SOURCES = rrr_stats.c main.c
rrr_stats_CFLAGS = ${AM_CFLAGS} -fpie
rrr_stats_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie
rrr_stats_LDADD = -levent

rrr_msgdb_SOURCES = rrr_msgdb.c main.c paths.c
rrr_msgdb_CFLAGS = ${AM_CFLAGS} -fpie
rrr_msgdb_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

rrr_msg_SOURCES = rrr_msg.c main.c
rrr_msg_CFLAGS = ${AM_CFLAGS} -fpie
rrr_msg_LDFLAGS = -L./lib/.libs -lrrr ${perl5_ldflags} -pie

if RRR_WITH_PERL5
all-local:
	echo "Generating Perl Makefile" && cd ${top_srcdir}/src/perl5/xsub && rm -f Makefile && ${PERL5_INTERPRETER} ./Makefile.PL && echo "Making perl xsub" && make
install-data-local:
	echo "Generating Perl Makefile" && cd ${top_srcdir}/src/perl5/xsub && rm -f Makefile && ${PERL5_INTERPRETER} ./Makefile.PL && echo "Making perl xsub" && make install
clean-local:
	cat paths.c.tmpl > paths.c; \
	echo "Generating Perl Makefile" && cd ${top_srcdir}/src/perl5/xsub && rm -f Makefile && ${PERL5_INTERPRETER} ./Makefile.PL && echo "Cleaning perl xsub" && make clean
else
clean-local:
	cat paths.c.tmpl > paths.c
endif
distclean-local:
	rm -f make-paths.sh

# Re-compile binaries using paths.c to give them udpated paths with install prefix
# Currently this is not safe for installed binaries, as autotools does not guarantee that 
# install-exec-local is run prior to install-exec, hence the "old" version might be installed
# rrr_msgdb is currently a non-installed binary
install-exec-local:
	chmod +x ./make-paths.sh && ./make-paths.sh paths.c ${DESTDIR}${datadir} && \
	make rrr_msgdb
