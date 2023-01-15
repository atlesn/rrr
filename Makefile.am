ACLOCAL_AMFLAGS = -I m4
if RRR_WITH_PERL5
	perl_dir = src/perl5/xsub
endif
SUBDIRS = src misc $(perl_dir)

clean-local:
	find * | grep '.gcno' | xargs rm -f; find * | grep '.gcda' | xargs rm -f; find * | grep '.gcov' | xargs rm -f; rm -rf lcov; rm -f main_coverage.info; true
