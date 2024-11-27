if RRR_WITH_JS
libtestjs_la_SOURCES = testjs.cxx
libtestjs_la_CXXFLAGS = ${JS_CXXFLAGS} ${AM_CXXFLAGS} -fpie -fPIE
libtestjs_la_LDFLAGS = -L${top_srcdir}/src/lib/.libs ${JS_LDFLAGS}
libtestjs_la_LIBADD = $(JS_LIBS) -lrrr -lrrrcxx 
js_extra_libraries = libtestjs.la
endif

noinst_LTLIBRARIES = ${js_extra_libraries}
