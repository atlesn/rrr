if RRR_WITH_NODE
libtestjs_la_SOURCES = testjs.cxx
libtestjs_la_CXXFLAGS = ${NODE_CXXFLAGS} ${AM_CXXFLAGS}
libtestjs_la_LDFLAGS = -L${top_srcdir}/src/lib/.libs -lrrr ${NODE_LDFLAGS} ${NODE_LIBS}
js_extra_libraries = libtestjs.la
endif

noinst_LTLIBRARIES = ${js_extra_libraries}
