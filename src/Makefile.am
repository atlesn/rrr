SUBDIRS = lib modules
bin_PROGRAMS = vlogger
vlogger_LDFLAGS = -ldl -lpthread -L./lib -lvlogger 
vlogger_SOURCES = voltagelogger.c cmdlineparser/cmdline.c modules.c
vlogger_CFLAGS = -DVL_MODULE_PATH="\"${libdir}/voltagelogger\""
