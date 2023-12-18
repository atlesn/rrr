#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub config {
	my $settings = shift;

	return 1;
}

sub get_from_tag {
	my $message = shift;
	my $tag = shift;

	return ($message->get_tag_all($tag))[0];
}

sub push_blob {
	my $message = shift;
	my $tag = shift;
	my $value = shift;

	$message->push_tag_blob($tag, $value, length $value);
}

sub process {
	my $message = shift;

	my($ip, $port) = $message->ip_get();

	return 1 unless defined $ip;

	printf("ip: $ip, port: $port\n");

	$message->clear_array();

	push_blob($message, "reply", "A\r");
	$message->send();

	return 1;
}
