#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_counter = 0;

sub push_host {
	my $message = shift;
	my $tag = shift;
	my $value = shift;

	push @{$message->{'array_values'}}, "$value";
	push @{$message->{'array_tags'}}, $tag;
	push @{$message->{'array_types'}}, "h";
}

sub source {
	my $message = shift;

	print "Spawn message with counter $global_counter\n";

	push_host($message, "counter", $global_counter++);

	$message->send();

	return 1;
}
