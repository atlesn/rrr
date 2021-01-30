#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $global_settings = undef;

my $count = 0;

sub source {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	my $t = time();
	my $r = rand(10000);

	$message->{'topic'} = "http/blabla/" . $t . "-" . $r;

#	my $port = (++$count % 2 == 0 ? "443" : "80");
#	my $method = (++$count % 2 == 0 ? "GET" : "PUT");

	$message->push_tag("http_server", "localhost");
	$message->push_tag("http_endpoint", "/redirect.php?c=$r");
#	$message->push_tag("http_method", $method);
#	$message->push_tag("http_port", $port);
#	$message->push_tag("http_port", "443");
	$message->push_tag("http_method", "PUT");
	$message->push_tag("http_format", "urlencoded");
	$message->push_tag("http_port", "80");
	$message->push_tag("a", "aaa");
	$message->push_tag("b", "bbbbbbbbb");

	if (++$count % 4 == 0) {
		$message->push_tag("http_body", "BODY BODY\0BODY\0BODY");
		$message->push_tag("http_content_type", "content/type");
	}

	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

