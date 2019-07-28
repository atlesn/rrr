SUBDIRS = lib/
bin_PROGRAMS = bdl

bdl_CFLAGS = -include $(top_srcdir)/config.h
bdl_LDFLAGS = -Wl,--no-as-needed -rdynamic
bdl_LDADD = lib/libbdl.la
bdl_SOURCES = bdl.c
