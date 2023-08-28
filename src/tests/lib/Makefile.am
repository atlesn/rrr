if RRR_WITH_NODE
libtestjs_la_SOURCES = testjs.cxx
libtestjs_la_CXXFLAGS = ${NODE_CXXFLAGS} ${AM_CXXFLAGS} -fpie -fPIE
libtestjs_la_LDFLAGS = -L${top_srcdir}/src/lib/.libs ${NODE_LDFLAGS}
libtestjs_la_LIBADD = $(NODE_LIBS) -lstdc++ -lrrr -lrrrcxx 
js_extra_libraries = libtestjs.la
endif

noinst_LTLIBRARIES = ${js_extra_libraries}
