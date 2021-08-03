#!/usr/bin/perl

my %allocated;

while (<STDIN>) {
	if (/Allocate.*= (\S+)/) {
		if (defined $allocated{$1}) {
			printf("Double allocation $1\n");
		}
		else {
			$allocated{$1} = 1;
		}
	}
	elsif (/Free.*= (\S+)/) {
		if (!defined $allocated{$1}) {
			printf("Double free $1\n");
		}
		else {
			printf("Free $1 OK\n");
			delete $allocated{$1};
		}
	}
	print;
}
