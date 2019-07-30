#!/usr/bin/perl -w

use rrr::rrr_helper::rrr_socket qw(rand);

print "Perl works!\n" . rand() . "\n";

foreach my $entry ( keys %rrr::rrr_helper::rrr_socket:: ) {
	print "Entry: $entry\n";
	no strict 'refs';
	if (defined &{"rrr::rrr_helper::rrr_socket::$entry"}) {
		print "sub $entry is defined\n" ;
	}
}
