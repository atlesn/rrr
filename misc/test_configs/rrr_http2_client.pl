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

#	if ($count++ >= 3) {
#		return 1;
#	}

	my $t = time();
	my $r = rand(10000);

	$message->{'topic'} = "http/blabla/$count"; #" . $t . "-" . $r;

#	my $port = (++$count % 2 == 0 ? "443" : "80");
#	my $method = (++$count % 2 == 0 ? "GET" : "PUT");

	$message->push_tag("http_server", "localhost");
	$message->push_tag("http_endpoint", "/$r");
#	$message->push_tag("http_method", $method);
#	$message->push_tag("http_port", $port);
	$message->push_tag("http_port", "4431");
#	$message->push_tag("http_port", "8001");
	$message->push_tag("http_method", "PUT");
	$message->push_tag("http_format", "multipart");
#	$message->push_tag("http_port", "80");
	$message->push_tag("a", "aaa");
	$message->push_tag("b", "bbbbbbbbb");

	$message->push_tag("http_body", "Message $count");
	$message->push_tag("http_content_type", "text/plain");

	$message->send();

	$count++;

	# Return 1 for success and 0 for error
	return 1;
}

my %received;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	my $response_code = ($message->get_tag_all("response_code"))[0];

#	$debug->msg(1, "Data '" . $message->{'data'} . "'\n");

	$message->{'data'} =~ /(\d+)/;

	$debug->msg(1, "Dup $1\n") if (defined ($received{$1}));

	$received{$1} = 1;

	my $receive_count = scalar keys %received;

	$debug->msg(1, "Received response - Sent $count<>$receive_count Received\n") if ($receive_count % 1000 == 0);

	return 1;
}
