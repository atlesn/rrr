lib_LTLIBRARIES = dummy.la stdout.la

module_ldflags=-module -avoid-version -shared

dummy_la_LDFLAGS = ${module_ldflags}
dummy_la_SOURCES = src_dummy.c

stdout_la_LDFLAGS = ${module_ldflags}
stdout_la_SOURCES = dst_stdout.c

libdir=${exec_prefix}/lib/voltagelogger
