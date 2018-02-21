bin_PROGRAMS = vlogger
vlogger_LDFLAGS = -ldl -lpthread
vlogger_SOURCES = voltagelogger.c cmdlineparser/cmdline.c modules.c buffer.c threads.c read.c
vlogger_CFLAGS = -DVL_MODULE_PATH="\"${libdir}/voltagelogger\"" -fPIC -Wmissing-braces
SUBDIRS = modules
