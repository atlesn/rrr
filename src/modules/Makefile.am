AM_CFLAGS = @AM_CFLAGS@ -fpie
module_ldflags=-module -avoid-version -shared -L../lib -pie

if RRR_WITH_MYSQL
mysql = mysql.la
mysql_la_SOURCES = p_mysql.c
mysql_la_CFLAGS = ${MYSQL_CFLAGS} ${AM_CFLAGS}
mysql_la_LDFLAGS = ${module_ldflags} ${MYSQL_LDFLAGS} -lrrrmysql
endif

if RRR_WITH_PYTHON3
python3 = python3.la
python3_la_SOURCES = p_python3.c
python3_la_CFLAGS = ${PYTHON3_CFLAGS} ${AM_CFLAGS}
# Python3 libraries are linked in librrr
python3_la_LDFLAGS = ${module_ldflags} -lrrrpython3
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

if RRR_WITH_LUA
lua = lua.la
lua_la_SOURCES = p_lua.c
lua_la_CFLAGS = ${LUA_CFLAGS} ${AM_CFLAGS}
# Lua libraries are linked in librrr
lua_la_LDFLAGS = ${module_ldflags}
endif

if RRR_WITH_JS
js = js.la
js_la_SOURCES = p_js.cxx
js_la_CXXFLAGS = ${AM_CXXFLAGS} ${JS_CXXFLAGS}
js_la_LDFLAGS = ${module_ldflags} -lrrrcxx ${JS_LDFLAGS} ${JS_LIBS}
endif

if RRR_WITH_ARTNET
artnet = artnet.la
artnet_la_SOURCES = p_artnet.c
artnet_la_LDFLAGS = ${module_ldflags}
endif

lib_LTLIBRARIES = dummy.la raw.la \
	ipclient.la ip.la averager.la file.la exploder.la mangler.la \
	buffer.la mqttbroker.la mqttclient.la socket.la \
	influxdb.la journal.la cmodule.la httpclient.la httpserver.la \
	msgdb.la incrementer.la cacher.la raft.la modbus.la \
	${mysql} ${python3} ${voltmonitor} ${perl5} ${lua} ${js} ${artnet}

mqttbroker_la_LDFLAGS = ${module_ldflags}
mqttbroker_la_SOURCES = d_mqttbroker.c

msgdb_la_LDFLAGS = ${module_ldflags}
msgdb_la_SOURCES = d_msgdb.c

incrementer_la_LDFLAGS = ${module_ldflags}
incrementer_la_SOURCES = p_incrementer.c

cacher_la_LDFLAGS = ${module_ldflags}
cacher_la_SOURCES = p_cacher.c

raft_la_LDFLAGS = ${module_ldflags}
raft_la_SOURCES = p_raft.c

mqttclient_la_LDFLAGS = ${module_ldflags}
mqttclient_la_SOURCES = p_mqttclient.c

dummy_la_LDFLAGS = ${module_ldflags}
dummy_la_SOURCES = src_dummy.c

raw_la_LDFLAGS = ${module_ldflags}
raw_la_SOURCES = d_raw.c

averager_la_LDFLAGS = ${module_ldflags}
averager_la_SOURCES = p_averager.c

ipclient_la_LDFLAGS = ${module_ldflags} 
ipclient_la_SOURCES = p_ipclient.c

buffer_la_LDFLAGS = ${module_ldflags}
buffer_la_SOURCES = p_buffer.c

exploder_la_LDFLAGS = ${module_ldflags}
exploder_la_SOURCES = p_exploder.c

mangler_la_LDFLAGS = ${module_ldflags}
mangler_la_SOURCES = p_mangler.c

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

httpclient_la_LDFLAGS = ${module_ldflags}
httpclient_la_SOURCES = p_httpclient.c

httpserver_la_LDFLAGS = ${module_ldflags}
httpserver_la_SOURCES = p_httpserver.c

file_la_LDFLAGS = ${module_ldflags}
file_la_SOURCES = p_file.c

modbus_la_LDFLAGS = ${module_ldflags}
modbus_la_SOURCES = p_modbus.c

libdir=${exec_prefix}/lib/rrr
