#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $count = 0;

sub send_message {
	my $message = shift;
	my $server = shift;
	my $port = shift;

	$message->clear_array();

	# Should be filtered out by http_meta_tags_ignore=yes
	$message->push_tag_str ("http_server", $server);
	$message->push_tag_str ("http_port", $port);

	# Should be filtered out by http_request_tags_ignore=yes
	$message->push_tag_str ("http_authority", "authority");
	$message->push_tag_str ("http_request_partials", "partials");

	$message->push_tag_str("my_value", "my_value");

	$message->send();
}

sub source {
	my $message = shift;

	send_message($message, "localhost", "8886");

	return 1;
}
