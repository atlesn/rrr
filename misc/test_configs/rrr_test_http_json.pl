#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	$message->push_tag_str("endpoint", "/json.php");

	$message->{'topic'} = "json.php"; 

	$message->send();

	return 1;
}
