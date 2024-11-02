#!/usr/bin/perl -w

# Input is comma separated hex values like 0x1,0x2,...

my $data;

while (<STDIN>) {
	s/\s+//g;
	$data .= $_;
}

foreach my $byte (split(",", $data)) {
	print chr(hex($byte));
}
