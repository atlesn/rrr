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

	if ($loops == 0) {
		$message->{'topic'} = "rrr/increment/A";
		$message->push_tag_str("id", "1");
		$message->send();
		$message->clear_array();

		$message->{'topic'} = "rrr/increment/B";
		$message->push_tag_str("id", "2");
		$message->send();
		$message->clear_array();

		$message->{'topic'} = "rrr/increment/C";
		$message->push_tag_str("id", "3");
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
