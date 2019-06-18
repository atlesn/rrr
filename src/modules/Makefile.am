if ENABLE_PYTHON3
lib_LTLIBRARIES = dummy.la raw.la averager.la voltmonitor.la \
	ipclient.la ipserver.la blockdev.la controller.la mysql.la python3.la
else
lib_LTLIBRARIES = dummy.la raw.la averager.la voltmonitor.la \
	ipclient.la ipserver.la blockdev.la controller.la mysql.la
endif

module_ldflags=-module -avoid-version -shared -L../lib -lrrr

if ENABLE_PYTHON3
python3_la_LDFLAGS = ${module_ldflags} ${PYTHON3_LDFLAGS}
python3_la_CFLAGS = ${PYTHON3_CFLAGS}
python3_la_SOURCES = p_python3.c
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

mysql_la_LDFLAGS = ${module_ldflags} -lmysqlclient
mysql_la_SOURCES = p_mysql.c

udpreader_la_LDFLAGS = ${module_ldflags}
udpreader_la_SOURCES = src_udpreader.c

libdir=${exec_prefix}/lib/rrr
