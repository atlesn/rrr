noinst_PROGRAMS = mqtt_parse mqtt_assemble array_parse msg_make

librrr_ldflags=${JEMALLOC_LIBS} -L../src/lib/.libs -lrrr
ldflags=${librrr_ldflags}

mqtt_parse_SOURCES = mqtt_parse.c ../src/main.c
mqtt_parse_CFLAGS = ${AM_CFLAGS} -fpie -O0
mqtt_parse_LDFLAGS = ${ldflags} -pie -O0

mqtt_assemble_SOURCES = mqtt_assemble.c ../src/main.c
mqtt_assemble_CFLAGS = ${AM_CFLAGS} -fpie -O0
mqtt_assemble_LDFLAGS = ${ldflags} -O0

array_parse_SOURCES = array_parse.c ../src/main.c
array_parse_CFLAGS = ${AM_CFLAGS} -fpie -O0
array_parse_LDFLAGS = ${ldflags} -O0

msg_make_SOURCES = msg_make.c ../src/main.c
msg_make_CFLAGS = ${AM_CFLAGS} -fpie -O0
msg_make_LDFLAGS = ${ldflags} -O0
