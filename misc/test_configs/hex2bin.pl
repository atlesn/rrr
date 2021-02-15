#!/usr/bin/perl -w

use strict;

while (<STDIN>) {
	chomp;
	s/\s+//g;

	while (s/^(..)//) {
		printf ("%c", hex($1));
	}
}
