if VL_WITH_OPENSSL
encryption = crypt.c module_crypt.c
endif

if VL_WITH_MYSQL
mysql = mysql.c
endif

lib_LTLIBRARIES = librrr.la
librrr_la_CFLAGS = ${AM_CFLAGS} ${OPENSSL_INCLUDES}
librrr_la_LDFLAGS = -lpthread -ldl -lm ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS} ${MYSQL_LDFLAGS}
librrr_la_SOURCES = buffer.c threads.c messages.c crc32.c cmdlineparser/cmdline.c ${encryption} \
					ip.c array.c type.c version.c configuration.c settings.c instance_config.c common.c \
					mqtt_broker.c mqtt_common.c mqtt_connection.c mqtt_packet.c mqtt_parse.c mqtt_property.c \
					mqtt_session.c mqtt_session_ram.c mqtt_assemble.c mqtt_payload_buf.c mqtt_subscription.c  \
					mqtt_topic.c mqtt_id_pool.c mqtt_client.c rrr_socket_msg.c rrr_socket_read.c rrr_socket_common.c \
					instances.c senders.c poll_helper.c modules.c rrr_socket.c udpstream.c udpstream_asd.c \
					utf8.c gnu.c base64.c map.c string_builder.c \
					http_session.c http_util.c http_fields.c http_part.c \
					fixed_point.c \
					${mysql}

if VL_WITH_PYTHON3
libadd_python3 = librrrpython3.la
noinst_python3 = librrrpython3.la
librrrpython3_la_SOURCES = python3.c python3_module.c python3_common.c python3_vl_message.c python3_socket.c python3_setting.c \
							python3_array.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\"
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS}
endif

if VL_WITH_PERL5_XSI
perl5_extrasources = perl5_xsi.c
endif

if VL_WITH_PERL5
libadd_perl5 = librrrperl5.la
noinst_perl5 = librrrperl5.la
librrrperl5_la_SOURCES = perl5.c ${perl5_extrasources}
librrrperl5_la_CFLAGS = ${PERL5_CFLAGS} 
librrrperl5_la_LDFLAGS = ${PERL5_LDFLAGS}
endif

librrr_la_LIBADD   = ${libadd_python3} ${libadd_perl5}
noinst_LTLIBRARIES = ${noinst_python3} ${noinst_perl5}
