includedir=${prefix}/include/rrr

nobase_include_HEADERS = *.h */*.h

input = input/input.c

if RRR_WITH_LINUX_INPUT
input_system = input/linux.c
endif

if RRR_WITH_FREEBSD_INPUT
input_system = input/linux.c
endif

if RRR_WITH_MYSQL
lib_mysql = librrrmysql.la
librrrmysql_la_SOURCES = mysql.c
librrrmysql_la_LDFLAGS = -lpthread -ldl -lm ${MYSQL_LDFLAGS} 
endif

if RRR_WITH_OPENSSL
encryption = rrr_openssl.c
endif
if RRR_WITH_OPENSSL_CRYPT
encryption = rrr_openssl.c
endif

if RRR_WITH_PYTHON3
lib_python3 = librrrpython3.la
librrrpython3_la_SOURCES = python3/python3_cmodule.c python3/python3_module.c python3/python3_common.c python3/python3_vl_message.c \
							python3/python3_socket.c python3/python3_array.c python3/python3_config.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\" ${AM_CFLAGS}
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS} ${AM_LDFLAGS}
endif

if RRR_WITH_PERL5
libadd_perl5 = librrrperl5.la
librrrperl5_la_SOURCES = perl5/perl5.c perl5/perl5_xsi.c perl5/perl5_types.c perl5/perl5_xsub.c
librrrperl5_la_CFLAGS = ${PERL5_CFLAGS} 
librrrperl5_la_LDFLAGS = ${PERL5_LDFLAGS}
perl5_extra_ld = ${PERL5_LDFLAGS}
endif

if RRR_WITH_NGHTTP2
libadd_nghttp2 = librrrnghttp2.la
librrrnghttp2_la_SOURCES = http2/http2.c
librrrnghttp2_la_CFLAGS = ${NGHTTP2_CFLAGS}
librrrnghttp2_la_LDFLAGS = ${NGHTTP2_LDFLAGS}
endif

mqtt =	mqtt/mqtt_broker.c mqtt/mqtt_common.c mqtt/mqtt_connection.c mqtt/mqtt_packet.c mqtt/mqtt_parse.c mqtt/mqtt_property.c \
	mqtt/mqtt_session.c mqtt/mqtt_session_ram.c mqtt/mqtt_assemble.c mqtt/mqtt_payload_buf.c mqtt/mqtt_subscription.c  \
	mqtt/mqtt_topic.c mqtt/mqtt_id_pool.c mqtt/mqtt_client.c mqtt/mqtt_acl.c mqtt/mqtt_transport.c

stats = stats/stats_engine.c stats/stats_instance.c stats/stats_message.c stats/stats_tree.c

socket =	socket/rrr_socket.c socket/rrr_socket_read.c \
			socket/rrr_socket_common.c socket/rrr_socket_client.c 

http =	http/http_session.c http/http_util.c http/http_fields.c http/http_part.c http/http_client.c \
		http/http_common.c http/http_query_builder.c http/http_client_config.c \
		http/http_server.c http/http_server_worker.c http/http_header_fields.c \
		http/http_part_parse.c http/http_part_multipart.c \
		http/http_application.c http/http_application_http1.c

websocket = websocket/websocket.c

cmodule =	cmodule/cmodule_main.c cmodule/cmodule_helper.c cmodule/cmodule_channel.c \
			cmodule/cmodule_ext.c cmodule/cmodule_worker.c

net_transport = net_transport/net_transport.c net_transport/net_transport_plain.c net_transport/net_transport_config.c

# posix.c is in libadd further down
util = util/gnu.c util/base64.c util/crc32.c util/rrr_time.c util/rrr_endian.c util/slow_noop.c util/utf8.c util/readfile.c

ip = ip/ip.c ip/ip_accept_data.c ip/ip_util.c

udpstream = udpstream/udpstream.c udpstream/udpstream_asd.c

message_holder = message_holder/message_holder.c message_holder/message_holder_util.c message_holder/message_holder_collection.c

messages = messages/msg_addr.c messages/msg_log.c messages/msg_msg.c messages/msg.c messages/msg_checksum.c

helpers = helpers/nullsafe_str.c

if RRR_WITH_OPENSSL
net_transport_tls = net_transport/net_transport_openssl.c net_transport/net_transport_tls_common.c
endif

if RRR_WITH_LIBRESSL
net_transport_libressl = net_transport/net_transport_libressl.c net_transport/net_transport_tls_common.c
endif

librrr_la_CFLAGS = ${OPENSSL_INCLUDES} ${LIBRESSL_LIBTLS_CFLAGS} ${AM_CFLAGS}
librrr_la_LDFLAGS = ${OPENSSL_LDFLAGS} ${LIBRESSL_LIBTLS_LDFLAGS} ${perl5_extra_ld}
librrr_la_SOURCES = buffer.c threads.c cmdlineparser/cmdline.c rrr_config.c \
					version.c configuration.c parse.c settings.c instance_config.c common.c \
					message_broker.c map.c array.c array_tree.c \
					read.c rrr_mmap.c mmap_channel.c \
					instances.c instance_friends.c poll_helper.c modules.c \
					string_builder.c random.c condition.c \
					fixed_point.c passwd.c environment_file.c \
					${encryption} ${mqtt} ${stats} ${socket} ${http} ${cmodule} ${udpstream} \
					${net_transport} ${net_transport_tls} ${net_transport_libressl} \
					${util} ${ip} ${message_holder} ${messages} \
					${input} ${input_system} ${helpers} ${websocket}

lib_LTLIBRARIES = librrr.la	${lib_python3} ${lib_mysql}

libadd_rrr_posix = librrr_posix.la
librrr_posix_la_SOURCES = util/posix.c
librrr_posix_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT
librrr_posix_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_conversion_warning = librrr_conversion_warning.la
librrr_conversion_warning_la_SOURCES = type.c
librrr_conversion_warning_la_CFLAGS = -Wconversion ${AM_CFLAGS}
librrr_conversion_warning_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_readdir = librrr_readdir.la
librrr_readdir_la_SOURCES = util/rrr_readdir.c
librrr_readdir_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_READDIR ${AM_CFLAGS}
librrr_readdir_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_strerror = librrr_strerror.la
librrr_strerror_la_SOURCES = rrr_strerror.c
librrr_strerror_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_STRERROR ${AM_CFLAGS}
librrr_strerror_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_fork = librrr_fork.la
librrr_fork_la_SOURCES = fork.c
librrr_fork_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_FORK ${AM_CFLAGS}
librrr_fork_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_log = librrr_log.la
librrr_log_la_SOURCES = log.c
librrr_log_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_PRINTF ${AM_CFLAGS}
librrr_log_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_umask = librrr_umask.la
librrr_umask_la_SOURCES = rrr_umask.c
librrr_umask_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_UMASK ${AM_CFLAGS}
librrr_umask_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_sha1 = sha1/libsha1.la
sha1_libsha1_la_SOURCES = sha1/sha1.c

libadd_all =	${libadd_perl5}					\
				${libadd_nghttp2}				\
				${libadd_rrr_readdir}			\
				${libadd_rrr_strerror}			\
				${libadd_rrr_fork}				\
				${libadd_rrr_log}				\
				${libadd_rrr_umask}				\
				${libadd_rrr_conversion_warning}\
				${libadd_rrr_posix}				\
				${libadd_rrr_sha1}

noinst_LTLIBRARIES = ${libadd_all}
librrr_la_LIBADD = ${libadd_all} ${LIBRESSL_LIBTLS_LIBADD} ${OPENSSL_LIBS} ${JOURNALD_LIBS} -lpthread -ldl -lm
