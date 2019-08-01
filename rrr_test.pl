#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;

print "Perl works!\n";

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

	for ($i = 0; $i < 10; $i++) {
		$message->send();
	}

#	print_value($message, 'timestamp_from');
#	print_value($message, 'data');

	return 0;
}
