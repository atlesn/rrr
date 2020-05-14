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

sub get_from_tag {
	my $message = shift;
	my $tag = shift;

	for (my $i = 0; $i < @{$message->{'array_tags'}}; $i++) {
		if (@{$message->{'array_tags'}}[$i] eq $tag) {
			return @{$message->{'array_values'}}[$i];
		}
	}

	return undef;
}

sub source {
	my $message = shift;

	print "Spawn message with counter $global_counter\n";

	push_host($message, "counter", $global_counter++);

	$message->{'timestamp'} = rand(10000);

	$message->send();

	return 1;
}

sub process {
	my $message = shift;

	my $counter = get_from_tag($message, "counter");

	print "\tReceive counter " . @{$counter}[0] . " timestamp " . $message->{'timestamp'} . "\n";

	return 1;
}
