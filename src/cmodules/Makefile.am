AM_CFLAGS = @AM_CFLAGS@ -Wextra
libdir=${exec_prefix}/lib/rrr/cmodules
cmodule_ldflags=-module -avoid-version -shared -L../lib/.libs -lrrr
cmodule_cflags=@AM_CFLAGS@ -I../lib

all-local:
	./verify_targets.sh

dummy_la_CFLAGS = ${cmodule_cflags}
dummy_la_LDFLAGS = ${cmodule_ldflags}
dummy_la_SOURCES = dummy.c
lib_LTLIBRARIES = dummy.la
