AM_CFLAGS = @AM_CFLAGS@ -Wextra

if RRR_WITH_MYSQL
mysql = mysql.la
mysql_la_SOURCES = p_mysql.c
mysql_la_CFLAGS = ${MYSQL_CFLAGS} ${AM_CFLAGS}
mysql_la_LDFLAGS = ${module_ldflags} ${MYSQL_LDFLAGS}
endif

if RRR_WITH_PYTHON3
python3 = python3.la
python3_la_SOURCES = p_python3.c
python3_la_CFLAGS = ${PYTHON3_CFLAGS} ${AM_CFLAGS}
# Python3 libraries are linked in librrr
python3_la_LDFLAGS = ${module_ldflags}
endif

# A non-working version of voltmonitor is compiled if usb is disabled 
if RRR_WITH_USB
libusb=-lusb
endif
voltmonitor = voltmonitor.la
voltmonitor_la_SOURCES = src_voltmonitor.c
voltmonitor_la_LDFLAGS = ${module_ldflags} ${libusb}

if RRR_WITH_PERL5
perl5 = perl5.la
perl5_la_SOURCES = p_perl5.c
perl5_la_CFLAGS = ${PERL5_CFLAGS} ${AM_CFLAGS}
# Perl5 libraries are linked in librrr
perl5_la_LDFLAGS = ${module_ldflags}
endif

lib_LTLIBRARIES = dummy.la raw.la buffer.la \
	ipclient.la ip.la averager.la \
	duplicator.la mqttbroker.la mqttclient.la socket.la \
	influxdb.la journal.la cmodule.la \
	${mysql} ${python3} ${voltmonitor} ${perl5}


module_ldflags=-module -avoid-version -shared -L../lib -lrrr 

mqttbroker_la_LDFLAGS = ${module_ldflags}
mqttbroker_la_SOURCES = d_mqttbroker.c

mqttclient_la_LDFLAGS = ${module_ldflags}
mqttclient_la_SOURCES = p_mqttclient.c

dummy_la_LDFLAGS = ${module_ldflags}
dummy_la_SOURCES = src_dummy.c

raw_la_LDFLAGS = ${module_ldflags}
raw_la_SOURCES = p_raw.c

averager_la_LDFLAGS = ${module_ldflags}
averager_la_SOURCES = p_averager.c

ipclient_la_LDFLAGS = ${module_ldflags} 
ipclient_la_SOURCES = p_ipclient.c

buffer_la_LDFLAGS = ${module_ldflags}
buffer_la_SOURCES = p_buffer.c

duplicator_la_LDFLAGS = ${module_ldflags}
duplicator_la_SOURCES = p_duplicator.c

ip_la_LDFLAGS = ${module_ldflags}
ip_la_SOURCES = p_ip.c

socket_la_LDFLAGS = ${module_ldflags}
socket_la_SOURCES = src_socket.c

influxdb_la_LDFLAGS = ${module_ldflags}
influxdb_la_SOURCES = p_influxdb.c

journal_la_LDFLAGS = ${module_ldflags}
journal_la_SOURCES = src_journal.c

cmodule_la_LDFLAGS = ${module_ldflags}
cmodule_la_SOURCES = p_cmodule.c

libdir=${exec_prefix}/lib/rrr
