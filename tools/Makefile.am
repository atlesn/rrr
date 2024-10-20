noinst_PROGRAMS = mqtt_parse mqtt_assemble

librrr_ldflags=${JEMALLOC_LIBS} -L../src/lib/.libs -lrrr
ldflags=${librrr_ldflags}

mqtt_parse_SOURCES = mqtt_parse.c ../src/main.c
mqtt_parse_CFLAGS = ${AM_CFLAGS} -fpie
mqtt_parse_LDFLAGS = ${ldflags} -pie

mqtt_assemble_SOURCES = mqtt_assemble.c ../src/main.c
mqtt_assemble_CFLAGS = ${AM_CFLAGS} -fpie
mqtt_assemble_LDFLAGS = ${ldflags}
