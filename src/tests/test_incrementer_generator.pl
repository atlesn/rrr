#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

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
