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

if RRR_WITH_PYTHON3
libadd_python3 = librrrpython3.la
librrrpython3_la_SOURCES = python3/python3_cmodule.c python3/python3_module.c python3/python3_common.c python3/python3_message.c \
                           python3/python3_socket.c python3/python3_array.c python3/python3_config.c
librrrpython3_la_CFLAGS = ${PYTHON3_CFLAGS} -DRRR_PYTHON3_SITE_PACKAGES_DIR=\"${pythondir}\" -DRRR_PYTHON3_PKGDIR=\"${pkgpythondir}\" ${AM_CFLAGS}
librrrpython3_la_LDFLAGS = ${PYTHON3_LDFLAGS} ${AM_LDFLAGS}
python3_extra_ld = ${PYTHON3_LDFLAGS}
endif

if RRR_WITH_PERL5
libadd_perl5 = librrrperl5.la
librrrperl5_la_SOURCES = perl5/perl5.c perl5/perl5_xsi.c perl5/perl5_types.c perl5/perl5_xsub.c
librrrperl5_la_CFLAGS = ${PERL5_CFLAGS} 
librrrperl5_la_LDFLAGS = ${PERL5_LDFLAGS}
perl5_extra_ld = ${PERL5_LDFLAGS}
endif

if RRR_WITH_ARTNET
libadd_artnet = librrrartnet.la
librrrartnet_la_SOURCES = artnet/rrr_artnet.c
librrrartnet_la_CFLAGS = ${ARTNET_CFLAGS} 
librrrartnet_la_LDFLAGS = ${ARTNET_LDFLAGS}
librrrartnet_la_LIBS = ${ARTNET_LIBS}
artnet_extra_ld = ${ARTNET_LDFLAGS} ${ARTNET_LIBS}
endif

if RRR_WITH_LUA
libadd_lua = librrrlua.la
librrrlua_la_SOURCES = lua/lua.c \
                       lua/lua_message.c \
		       lua/lua_config.c \
		       lua/lua_debug.c \
		       lua/lua_cmodule.c
librrrlua_la_CFLAGS = ${LUA_CFLAGS} ${AM_CFLAGS}
librrrlua_la_LDFLAGS = ${LUA_LDFLAGS}
lua_extra_ld = ${LUA_LDFLAGS}
endif

if RRR_WITH_NGHTTP2
libadd_nghttp2 = librrrnghttp2.la
librrrnghttp2_la_SOURCES = http2/http2.c http/http_application_http2.c
librrrnghttp2_la_CFLAGS = ${NGHTTP2_CFLAGS} ${AM_CFLAGS}
librrrnghttp2_la_LDFLAGS = ${NGHTTP2_LDFLAGS}
nghttp2_extra_ld = ${NGHTTP2_LDFLAGS}
endif

if RRR_WITH_HTTP3
libadd_http3 = librrrhttp3.la
librrrhttp3_la_SOURCES = http3/http3.c http/http_application_http3.c
librrrhttp3_la_CFLAGS = ${HTTP3_CFLAGS} ${AM_CFLAGS}
librrrhttp3_la_LDFLAGS = ${HTTP3_LDFLAGS}
http3_extra_ld = ${HTTP3_LDFLAGS}

libadd_quic = librrrquic.la
librrrquic_la_SOURCES = net_transport/net_transport_quic.c
librrrquic_la_CFLAGS = ${GNUTLS_CFLAGS} ${AM_CFLAGS}
librrrquic_la_LDFLAGS = ${GNUTLS_LIBS}
quic_extra_ld = ${GNUTLS_LIBS} ${NGTCP2_LDFLAGS}
endif

if RRR_WITH_JSONC
libadd_jsonc = librrrjsonc.la
librrrjsonc_la_SOURCES = json/json.c
librrrjsonc_la_CFLAGS = ${JSONC_CFLAGS} ${AM_CFLAGS}
librrrjsonc_la_LDFLAGS = ${JSONC_LDFLAGS}
librrrjsonc_la_LIBS = ${JSONC_LIBS}
jsonc_extra_ld = ${JSONC_LDFLAGS} ${JSONC_LIBS}
endif

if RRR_WITH_ZLIB
libadd_zlib = librrrzlib.la
librrrzlib_la_SOURCES = zlib/rrr_zlib.c
librrrzlib_la_CFLAGS = ${ZLIB_CFLAGS} ${AM_CFLAGS}
librrrzlib_la_LDFLAGS = ${ZLIB_LDFLAGS}
zlib_extra_ld = ${ZLIB_LDFLAGS}
endif

if RRR_WITH_JS
libadd_js = librrrjs.la
librrrjs_la_SOURCES = js/Js.cxx js/Message.cxx js/Config.cxx js/Timeout.cxx js/OS.cxx js/EventQueue.cxx js/Persistent.cxx
librrrjs_la_CXXFLAGS = ${JS_CXXFLAGS} ${AM_CXXFLAGS}
librrrjs_la_LDFLAGS = ${JS_LDFLAGS} ${JS_LIBS}
js_extra_ld = ${JS_LDFLAGS}
js_extra_libadd = $(JS_LIBS)
endif

if RRR_WITH_TLS
net_transport_tls = net_transport/net_transport_tls_common.c
endif
if RRR_WITH_HTTP3
net_transport_tls = net_transport/net_transport_tls_common.c
endif

if RRR_WITH_OPENSSL_CRYPT
libadd_rrrcrypto = librrrcrypto.la
librrrcrypto_la_SOURCES = rrr_openssl.c
librrrcrypto_la_CFLAGS = ${CRYPTO_CFLAGS} ${AM_CFLAGS}
librrrcrypto_la_LDFLAGS = ${CRYPTO_LDFLAGS}
librrrcrypto_la_LIBADD = ${CRYPTO_LIBADD}
crypto_extra_ld = ${CRYPTO_LDFLAGS}
crypto_extra_libadd = ${CRYPTO_LIBADD}
endif

if RRR_WITH_OPENSSL
libadd_rrropenssl = librrropenssl.la
librrropenssl_la_SOURCES = net_transport/net_transport_openssl_common.c net_transport/net_transport_openssl.c
librrropenssl_la_CFLAGS = ${OPENSSL_CFLAGS} ${AM_CFLAGS}
librrropenssl_la_LDFLAGS = ${OPENSSL_LDFLAGS}
librrropenssl_la_LIBADD = ${OPENSSL_LIBADD}
openssl_extra_ld = ${OPENSSL_LDFLAGS}
openssl_extra_libadd = ${OPENSSL_LIBADD}
endif

if RRR_WITH_LIBRESSL
libadd_rrrlibressl = librrrlibressl.la
librrrlibressl_la_SOURCES = net_transport/net_transport_libressl.c
librrrlibressl_la_CFLAGS = ${LIBRESSL_CFLAGS} ${AM_CFLAGS}
librrrlibressl_la_LDFLAGS = ${LIBRESSL_LDFLAGS}
librrrlibressl_la_LIBADD = ${LIBRESSL_LIBADD}
libressl_extra_ld = ${LIBRESSL_LDFLAGS}
libressl_extra_libadd = ${LIBRESSL_LIBADD}
endif

if RRR_WITH_RAFT
libadd_rrrraft = librrrraft.la
librrrraft_la_SOURCES = raft/rrr_raft.c
librrrraft_la_CFLAGS = ${RAFT_CFLAGS} ${AM_CFLAGS}
librrrraft_la_LIBADD = ${RAFT_LIBS}
librrrraft_extra_libadd = ${RAFT_LIBS}
endif

mqtt = mqtt/mqtt_broker.c mqtt/mqtt_common.c mqtt/mqtt_connection.c mqtt/mqtt_packet.c mqtt/mqtt_parse.c mqtt/mqtt_property.c \
       mqtt/mqtt_session.c mqtt/mqtt_session_ram.c mqtt/mqtt_assemble.c mqtt/mqtt_payload_buf.c mqtt/mqtt_subscription.c  \
       mqtt/mqtt_topic.c mqtt/mqtt_id_pool.c mqtt/mqtt_client.c mqtt/mqtt_acl.c mqtt/mqtt_transport.c \
       mqtt/mqtt_payload.c mqtt/mqtt_usercount.c

stats = stats/stats_engine.c stats/stats_instance.c stats/stats_message.c stats/stats_tree.c

socket = socket/rrr_socket.c socket/rrr_socket_read.c socket/rrr_socket_send_chunk.c \
         socket/rrr_socket_common.c socket/rrr_socket_client.c socket/rrr_socket_graylist.c \
	 socket/rrr_socket_eventfd.c 

http = http/http_session.c http/http_util.c http/http_fields.c http/http_part.c http/http_client.c \
       http/http_common.c http/http_query_builder.c http/http_client_config.c \
       http/http_server.c http/http_header_fields.c http/http_service.c \
       http/http_part_parse.c http/http_part_multipart.c http/http_transaction.c \
       http/http_application.c http/http_application_http1.c http/http_application_http2_http3_common.c \
       http/http_redirect.c http/http_stream.c

websocket = websocket/websocket.c

modbus = modbus/rrr_modbus.c

cmodule = cmodule/cmodule_main.c cmodule/cmodule_helper.c cmodule/cmodule_channel.c \
          cmodule/cmodule_ext.c cmodule/cmodule_worker.c

net_transport = net_transport/net_transport.c net_transport/net_transport_plain.c net_transport/net_transport_config.c \
                net_transport/net_transport_ctx.c net_transport/net_transport_common.c net_transport/net_transport_connection_id.c

# posix.c and gnu.c is in libadd further down
util = util/base64.c util/crc32.c util/rrr_time.c util/rrr_endian.c \
       util/slow_noop.c util/utf8.c util/readfile.c util/hex.c \
       util/increment.c util/sha256.c util/arguments.c util/fs.c

ip = ip/ip.c ip/ip_accept_data.c ip/ip_util.c ip/ip_helper.c

udpstream = udpstream/udpstream.c udpstream/udpstream_asd.c

message_holder = message_holder/message_holder.c message_holder/message_holder_util.c message_holder/message_holder_collection.c \
                 message_holder/message_holder_slot.c

messages = messages/msg_addr.c messages/msg_log.c messages/msg_msg.c messages/msg.c messages/msg_checksum.c messages/msg_dump.c

helpers = helpers/nullsafe_str.c helpers/string_builder.c

msgdb = msgdb/msgdb_client.c msgdb/msgdb_server.c msgdb/msgdb_common.c

event = event/event.c event/event_collection.c

if RRR_WITH_CXX
lib_cxx=librrrcxx.la

util_cxx = util/Readfile.cxx

event_cxx = event/Event.cxx

librrrcxx_la_LDFLAGS = ${librrr_la_LDFLAGS} -L${top_srcdir}/src/lib/.libs \
		       ${js_extra_ld}
librrrcxx_la_CXXFLAGS = ${AM_CXXFLAGS} -DRRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT
librrrcxx_la_SOURCES = Array.cxx ${util_cxx} ${event_cxx}
endif

librrr_la_CFLAGS = ${AM_CFLAGS}
librrr_la_LDFLAGS = ${JEMALLOC_LIBS} \
                    ${LIBBSD_LIBS} \
                    ${TLS_LDFLAGS} \
                    ${perl5_extra_ld} \
                    ${artnet_extra_ld} \
                    ${lua_extra_ld} \
		    ${jsonc_extra_ld} \
		    ${nghttp2_extra_ld} \
		    ${python3_extra_ld} \
		    ${zlib_extra_ld} \
		    ${quic_extra_ld} \
		    ${http3_extra_ld} \
                    ${crypto_extra_ld} \
                    ${openssl_extra_ld} \
                    ${libressl_extra_ld}
librrr_la_CXXFLAGS = ${AM_CXXFLAGS} -DRRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT
librrr_la_SOURCES = fifo.c fifo_protected.c threads.c cmdlineparser/cmdline.c rrr_config.c \
                    version.c configuration.c parse.c settings.c instance_config.c common.c banner.c \
                    message_broker.c map.c array.c array_tree.c discern_stack.c discern_stack_helper.c message_helper.c \
                    read.c mmap_channel.c rrr_shm.c profiling.c \
                    instances.c instance_friends.c modules.c \
		    poll_helper.c msgdb_helper.c \
                    random.c condition.c \
                    fixed_point.c passwd.c environment_file.c \
                    serial/serial.c hdlc/hdlc.c \
		    rrr_mmap.c send_loop.c \
                    ${mqtt} ${stats} ${socket} ${http} ${cmodule} ${udpstream} \
                    ${net_transport} ${net_transport_quic} ${net_transport_tls} \
                    ${util} ${ip} ${message_holder} ${messages} \
                    ${input} ${input_system} ${helpers} ${websocket} ${modbus} \
		    ${msgdb} ${event}

lib_LTLIBRARIES =           \
        librrr.la           \
	${lib_mysql}        \
	${lib_cxx}

libadd_rrr_posix = librrr_posix.la
librrr_posix_la_SOURCES = util/posix.c
librrr_posix_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_PTHREAD_MUTEX_INIT ${AM_CFLAGS}
librrr_posix_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_gnu = librrr_gnu.la
librrr_gnu_la_SOURCES = util/gnu.c
librrr_gnu_la_CFLAGS = -DRRR_INTERCEPT_ALLOW_GETTID ${AM_CFLAGS}
librrr_gnu_la_LDFLAGS = -lpthread -ldl -lm

libadd_rrr_conversion_warning = librrr_conversion_warning.la
librrr_conversion_warning_la_SOURCES = type.c type_conversion.c
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

libadd_all =                         \
    ${libadd_python3}                \
    ${libadd_perl5}                  \
    ${libadd_artnet}                 \
    ${libadd_lua}                    \
    ${libadd_jsonc}                  \
    ${libadd_zlib}                   \
    ${libadd_nghttp2}                \
    ${libadd_http3}                  \
    ${libadd_quic}                   \
    ${libadd_rrr_readdir}            \
    ${libadd_rrr_strerror}           \
    ${libadd_rrr_fork}               \
    ${libadd_rrr_log}                \
    ${libadd_rrr_umask}              \
    ${libadd_rrr_conversion_warning} \
    ${libadd_rrr_posix}              \
    ${libadd_rrr_gnu}                \
    ${libadd_rrr_sha1}	             \
    ${libadd_rrrcrypto}              \
    ${libadd_rrropenssl}             \
    ${libadd_rrrlibressl}            \
    ${libadd_rrrraft}

if RRR_WITH_CXX
libadd_all_cxx =                     \
    ${libadd_js}
endif

noinst_LTLIBRARIES = ${libadd_all} ${libadd_all_cxx}
librrr_la_LIBADD =                   \
    ${libadd_all}                    \
    ${JOURNALD_LIBS}                 \
    ${LIBRT_LIBADD}                  \
    ${crypto_extra_libadd}           \
    ${openssl_extra_libadd}          \
    ${libressl_extra_libadd}         \
    ${librrrraft_extra_libadd}       \
    -lpthread                        \
    -ldl                             \
    -lm                              \
    -levent                          \
    -levent_pthreads

if RRR_WITH_CXX
librrrcxx_la_LIBADD = ${libadd_all_cxx} ${js_extra_libadd} -lpthread -ldl -lm -levent -levent_pthreads
endif
