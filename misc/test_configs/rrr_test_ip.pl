#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

sub config {
	my $settings = shift;

	print "Custom argument is '" . $settings->get("custom_argument") . "'\n";
	$settings->set("produce_warning_now", "abc");

	return 1;
}

my $id = 0;

sub source {
	my $message = shift;

	if ($id > 200) {
		return 1;
	}

	$message->push_tag_str("id", $id++);
	#$message->push_tag_str("data", "x" x (65536 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2));
	$message->push_tag_str("data", "x" x (3));

	$message->{'ip_addr'} = sockaddr_in (9100, inet_aton("127.0.0.1"));
	$message->{'ip_addr_len'} = bytes::length($message->{'ip_addr'});
	$message->{'ip_so_type'} = "tcp";

	$message->send();

	return 1;
}

sub process {
	my $message = shift;

	my $code = get_from_tag($message, "code");
	if (!defined($code)) {
		push_host($message, "code", $message->{'timestamp'});
#		printf "perl5: Could not find tag 'code' in message\n";
#		return 1;
	}

	my ($port, $ip_address) = unpack_sockaddr_in6 $message->{'ip_addr'};
	my $ip_str = inet_ntop AF_INET6, $ip_address; 
	print "Source: $ip_str:$port type " . $message->{'ip_so_type'} . "\n";

	$message->push_tag_blob($message, "reply", "A\r");

	$message->send();

#	$message->{'ip_addr'} = sockaddr_in (7777, inet_aton("127.0.0.1"));
#	$message->{'ip_addr_len'} = bytes::length($message->{'ip_addr'});
#	$message->{'ip_so_type'} = "tcp";

	$message->{'ip_addr'} = sockaddr_in (7777, inet_aton("127.0.0.1"));
	$message->{'ip_addr_len'} = bytes::length($message->{'ip_addr'});
	$message->{'ip_so_type'} = "udp";

	$message->send();

	foreach my $key (sort keys(%{$message})) {
		$debug->dbg(1, "Key: $key: " . $message->{$key} . "\n");
	}

	return 1;
}
