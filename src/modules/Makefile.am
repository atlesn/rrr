lib_LTLIBRARIES = dummy.la raw.la averager.la voltmonitor.la \
	ipclient.la ipserver.la blockdev.la controller.la

module_ldflags=-module -avoid-version -shared -L../lib -lvlogger

dummy_la_LDFLAGS = ${module_ldflags}
dummy_la_SOURCES = src_dummy.c

voltmonitor_la_LDFLAGS = ${module_ldflags}  -lusb 
voltmonitor_la_SOURCES = src_voltmonitor.c

raw_la_LDFLAGS = ${module_ldflags}
raw_la_SOURCES = p_raw.c

averager_la_LDFLAGS = ${module_ldflags}
averager_la_SOURCES = p_averager.c

ipclient_la_LDFLAGS = ${module_ldflags}
ipclient_la_SOURCES = p_ipclient.c common/ip.c

ipserver_la_LDFLAGS = ${module_ldflags}
ipserver_la_SOURCES = p_ipserver.c common/ip.c

blockdev_la_LDFLAGS = ${module_ldflags} -lbdl
blockdev_la_SOURCES = p_blockdev.c

controller_la_LDFLAGS = ${module_ldflags}
controller_la_SOURCES = p_controller.c

libdir=${exec_prefix}/lib/voltagelogger
