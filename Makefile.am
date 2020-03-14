ACLOCAL_AMFLAGS = -I m4
if RRR_WITH_PERL5
	perl_dir = src/perl5/xsub
endif
SUBDIRS = src misc $(perl_dir)

clean-local:
	find | grep '.gcno' | xargs rm; find | grep '.gcda' | xargs rm; find | grep '.gcov' | xargs rm; true
