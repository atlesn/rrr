if RRR_WITH_NODE
libtestjs_la_SOURCES = testjs.cxx
libtestjs_la_CXXFLAGS = ${AM_CXXFLAGS} ${NODE_CXXFLAGS}
libtestjs_la_LDFLAGS = ${NODE_LDFLAGS} ${NODE_LIBS} -L../../lib/.libs -lrrrcxx -lrrr
js_extra_libraries = libtestjs.la
endif

noinst_LTLIBRARIES = ${js_extra_libraries}
