#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $loops = 0;

sub source {
	my $message = shift;

	# Max value in configuration is expected to be 32 bits (for instance 0xffffffff)

	my $prefix = 65535;

	if ($loops == 0) {
		my $value;

		$value = 1 | ($prefix << 32);

		$message->{'topic'} = "rrr/increment/A";
		$message->push_tag_str("id", $value);
		$message->send();
		$message->clear_array();

		$value = 2 | ($prefix << 32);

		$message->{'topic'} = "rrr/increment/B";
		$message->push_tag_str("id", $value);
		$message->send();
		$message->clear_array();

		$value = 3 | ($prefix << 32);

		$message->{'topic'} = "rrr/increment/C";
		$message->push_tag_str("id", $value);
		$message->send();
		$message->clear_array();
	}
	elsif ($loops == 3) {
		return 1;
	}

	$loops++;

	$message->{'topic'} = "rrr/increment/A";
	$message->send();

	$message->{'topic'} = "rrr/increment/B";
	$message->send();

	$message->{'topic'} = "rrr/increment/C";
	$message->send();

	return 1;
}

sub process {
	my $message = shift;


	return 1;
}
