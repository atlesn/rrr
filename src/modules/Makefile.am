module_ldflags=-module -avoid-version -shared -L../lib -lrrr

if RRR_TEST_MYSQL
lib_LTLIBRARIES = dummy.la raw.la averager.la voltmonitor.la \
	ipclient.la ipserver.la blockdev.la controller.la mysql.la \
	udpreader.la
mysql_la_LDFLAGS = ${module_ldflags} -lmysqlclient
mysql_la_SOURCES = p_mysql.c
else
lib_LTLIBRARIES = dummy.la raw.la averager.la voltmonitor.la \
	ipclient.la ipserver.la blockdev.la controller.la \
	udpreader.la
endif

dummy_la_LDFLAGS = ${module_ldflags}
dummy_la_SOURCES = src_dummy.c

voltmonitor_la_LDFLAGS = ${module_ldflags}  -lusb 
voltmonitor_la_SOURCES = src_voltmonitor.c

raw_la_LDFLAGS = ${module_ldflags}
raw_la_SOURCES = p_raw.c

averager_la_LDFLAGS = ${module_ldflags}
averager_la_SOURCES = p_averager.c

ipclient_la_LDFLAGS = ${module_ldflags} 
ipclient_la_SOURCES = p_ipclient.c

ipserver_la_LDFLAGS = ${module_ldflags}
ipserver_la_SOURCES = p_ipserver.c

blockdev_la_LDFLAGS = ${module_ldflags} -lbdl
blockdev_la_SOURCES = p_blockdev.c

controller_la_LDFLAGS = ${module_ldflags}
controller_la_SOURCES = p_controller.c

udpreader_la_LDFLAGS = ${module_ldflags}
udpreader_la_SOURCES = src_udpreader.c

libdir=${exec_prefix}/lib/rrr
