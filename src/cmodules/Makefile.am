AM_CFLAGS = @AM_CFLAGS@ -Wextra
libdir=@CMODULE_DIR@
cmodule_ldflags=-module -avoid-version -shared -L../lib/.libs -lrrr
cmodule_cflags=@AM_CFLAGS@ -I../lib

dummy_la_CFLAGS = ${cmodule_cflags} 
dummy_la_LDFLAGS = ${cmodule_ldflags} 
dummy_la_SOURCES = dummy.c dummy/extra.c

lib_LTLIBRARIES = dummy.la

if HAVE_GTK
sound_display_la_CFLAGS = ${cmodule_cflags} ${GTK_CFLAGS}
sound_display_la_LDFLAGS = ${cmodule_ldflags} ${GTK_LIBS}
sound_display_la_SOURCES = sound_display.c

lib_LTLIBRARIES += sound_display.la
endif
