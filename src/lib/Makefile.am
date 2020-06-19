if RRR_WITH_MYSQL
mysql = mysql.c
endif

if RRR_WITH_OPENSSL
encryption = rrr_openssl.c net_transport_tls.c
endif

if RRR_WITH_PYTHON3
libadd_python3 = librrrpython3.la
librrrpython3_la_SOURCES = python3.c python3_module.c python3_common.c python3_vl_message.c python3_setting.c python3_socket.c \
							python3_array.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\"
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS}
endif

if RRR_WITH_PERL5
libadd_perl5 = librrrperl5.la
librrrperl5_la_SOURCES = perl5.c perl5_xsi.c perl5_types.c
librrrperl5_la_CFLAGS = ${PERL5_CFLAGS} 
librrrperl5_la_LDFLAGS = ${PERL5_LDFLAGS}
perl5_extra_ld = ${PERL5_LDFLAGS}
endif

lib_LTLIBRARIES = librrr.la
librrr_la_CFLAGS = ${AM_CFLAGS} ${OPENSSL_INCLUDES}
librrr_la_LDFLAGS = -lpthread -ldl -lm ${MYSQL_LDFLAGS} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS} ${perl5_extra_ld}
librrr_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c \
					ip.c ip_accept_data.c ip_buffer_entry.c \
					array.c type.c version.c configuration.c parse.c settings.c instance_config.c common.c \
					mqtt_broker.c mqtt_common.c mqtt_connection.c mqtt_packet.c mqtt_parse.c mqtt_property.c \
					mqtt_session.c mqtt_session_ram.c mqtt_assemble.c mqtt_payload_buf.c mqtt_subscription.c  \
					mqtt_topic.c mqtt_id_pool.c mqtt_client.c mqtt_acl.c mqtt_transport.c \
					message_broker.c \
					rrr_socket_msg.c rrr_socket_read.c rrr_socket_common.c rrr_socket_client.c rrr_socket_msg_checksum.c \
					read.c message_addr.c message_log.c rrr_mmap.c mmap_channel.c \
					instances.c instance_collection.c poll_helper.c modules.c rrr_socket.c udpstream.c udpstream_asd.c \
					utf8.c gnu.c base64.c map.c string_builder.c random.c \
					stats_engine.c stats_instance.c stats_message.c stats_tree.c \
					http_session.c http_util.c http_fields.c http_part.c \
					net_transport.c net_transport_plain.c \
					fixed_point.c slow_noop.c rrr_endian.c posix.c passwd.c \
					${mysql} ${encryption}

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
