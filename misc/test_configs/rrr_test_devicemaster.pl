#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

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

sub process {
	my $message = shift;

	my $code = get_from_tag($message, "code");
	if (!defined($code)) {
		printf "perl5: Could not find tag 'code' in message\n";
		return 1;
	}

	push @{$message->{'array_values'}}, "A\r";
	push @{$message->{'array_tags'}}, "reply";
	push @{$message->{'array_types'}}, "str";

	$message->send();

	return 1;
}
