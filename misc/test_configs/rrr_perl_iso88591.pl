#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use Encode qw(from_to decode encode);
use utf8;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub process {
	my $message = shift;

	my $str = ($message->get_tag_all("str"))[0];

	from_to($str, "iso-8859-1", "utf8");

	utf8::decode($str);

	print "$str\n";

	$message->clear_tag("str");
	$message->push_tag("str", $str);

	$message->send();

	return 1;
}

