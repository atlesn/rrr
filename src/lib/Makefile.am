if RRR_WITH_MYSQL
mysql = mysql.c
endif

if RRR_WITH_OPENSSL
encryption = rrr_openssl.c
endif

if RRR_WITH_PYTHON3
libadd_python3 = librrrpython3.la
librrrpython3_la_SOURCES = python3/python3_cmodule.c python3/python3_module.c python3/python3_common.c python3/python3_vl_message.c \
							python3/python3_socket.c python3/python3_array.c python3/python3_config.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\"
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS}
endif

if RRR_WITH_PERL5
libadd_perl5 = librrrperl5.la
librrrperl5_la_SOURCES = perl5/perl5.c perl5/perl5_xsi.c perl5/perl5_types.c
librrrperl5_la_CFLAGS = ${PERL5_CFLAGS} 
librrrperl5_la_LDFLAGS = ${PERL5_LDFLAGS}
perl5_extra_ld = ${PERL5_LDFLAGS}
endif

mqtt =	mqtt/mqtt_broker.c mqtt/mqtt_common.c mqtt/mqtt_connection.c mqtt/mqtt_packet.c mqtt/mqtt_parse.c mqtt/mqtt_property.c \
	mqtt/mqtt_session.c mqtt/mqtt_session_ram.c mqtt/mqtt_assemble.c mqtt/mqtt_payload_buf.c mqtt/mqtt_subscription.c  \
	mqtt/mqtt_topic.c mqtt/mqtt_id_pool.c mqtt/mqtt_client.c mqtt/mqtt_acl.c mqtt/mqtt_transport.c

stats = stats/stats_engine.c stats/stats_instance.c stats/stats_message.c stats/stats_tree.c

socket =	socket/rrr_socket.c socket/rrr_socket_msg.c socket/rrr_socket_read.c \
			socket/rrr_socket_common.c socket/rrr_socket_client.c socket/rrr_socket_msg_checksum.c

http =	http/http_session.c http/http_util.c http/http_fields.c http/http_part.c http/http_client.c \
		http/http_common.c

cmodule =	cmodule/cmodule_main.c cmodule/cmodule_helper.c cmodule/cmodule_channel.c \
			cmodule/cmodule_ext.c cmodule/cmodule_defer_queue.c

net_transport = net_transport/net_transport.c net_transport/net_transport_plain.c net_transport/net_transport_config.c

if RRR_WITH_OPENSSL
net_transport_tls = net_transport/net_transport_tls.c
endif

lib_LTLIBRARIES = librrr.la
librrr_la_CFLAGS = ${AM_CFLAGS} ${OPENSSL_INCLUDES}
librrr_la_LDFLAGS = -lpthread -ldl -lm ${MYSQL_LDFLAGS} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS} ${perl5_extra_ld}
librrr_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c \
					ip.c ip_accept_data.c ip_buffer_entry.c \
					array.c type.c version.c configuration.c parse.c settings.c instance_config.c common.c \
					message_broker.c \
					read.c message_addr.c message_log.c rrr_mmap.c mmap_channel.c \
					instances.c instance_collection.c poll_helper.c modules.c udpstream.c udpstream_asd.c \
					utf8.c gnu.c base64.c map.c string_builder.c random.c \
					fixed_point.c slow_noop.c rrr_endian.c posix.c passwd.c \
					${mysql} ${encryption} ${mqtt} ${stats} ${socket} ${http} ${cmodule} \
					${net_transport} ${net_transport_tls}

libadd_rrr_readdir = librrr_readdir.la
librrr_readdir_la_SOURCES = rrr_readdir.c
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

libadd_all =	${libadd_perl5}			\
				${libadd_python3}		\
				${libadd_rrr_readdir}	\
				${libadd_rrr_strerror}	\
				${libadd_rrr_fork}		\
				${libadd_rrr_log}		\
				${libadd_rrr_umask}

noinst_LTLIBRARIES = ${libadd_all}
librrr_la_LIBADD =  ${libadd_all}
