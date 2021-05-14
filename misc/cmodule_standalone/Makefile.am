ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = @AM_CFLAGS@ -Wextra
libdir=@CMODULE_DIR@
cmodule_ldflags=-module -avoid-version -shared -lrrr
cmodule_cflags=@AM_CFLAGS@ 


dummy_la_CFLAGS = ${cmodule_cflags} 
dummy_la_LDFLAGS = ${cmodule_ldflags} 
dummy_la_SOURCES = dummy.c dummy/extra.c

lib_LTLIBRARIES = dummy.la
