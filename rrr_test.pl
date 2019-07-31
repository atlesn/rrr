#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_socket;

print "Perl works!\n";

my %message = (
	"timestamp_from" => 10
);

process(\%message);

sub print_value {
	my $self = shift;
	my $key = shift;

	print "$key: " . $self->{$key} . "\n";
}

sub source {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'} - 3;

	return 0;
}

sub process {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'} + 3;

#	print_value($message, 'timestamp_from');
#	print_value($message, 'data');

	return 0;
}
