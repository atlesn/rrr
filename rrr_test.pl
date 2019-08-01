#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

print "Perl works!\n";

sub print_value {
	my $self = shift;
	my $key = shift;

	print "$key: " . $self->{$key} . "\n";
}

sub config {
	my $settings = shift;

	print "abcdef: " . $settings->get("abcdef") . "\n";

	$settings->set("ghi", "789");

	print "ghi: " . $settings->get("ghi") . "\n";

	return 1;
}

sub source {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'} - 3;

	return 1;
}

sub process {
	my $message = shift;

	$message->{'timestamp_from'} = $message->{'timestamp_from'} + 3;

	for ($i = 0; $i < 2; $i++) {
		$message->send();
	}

#	print_value($message, 'timestamp_from');
#	print_value($message, 'data');

	return 1;
}
