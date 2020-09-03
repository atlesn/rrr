#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $timeout_s = 5;

my %responses;
my %active_handles;

my $req_id = 0;

sub send_response {
	my $message = shift;
	my $req = shift;
	my $code = shift;
	my $body = shift;

	$message->clear_array();

	$body =~ s/"/\\"/;

	my $json = "{
		\"content\": \"$body\",
		\"id\": " . $req->{"id"} . "
}";

	my $response = "";
	if ($code == 200) {
		$response = "HTTP/1.1 200 OK\r\n";
	}
	else {
		$response = "HTTP/1.1 500 Bad Request\r\n";
	}

	$response .= "Access-Control-Allow-Origin: *\r\n";

	$response .= "Content-Type: application/json; charset=UTF-8\r\n";
	$response .= "Content-Length: " . (length $json) . "\r\n\r\n$json";

	$req->{'topic'} =~ s/request/raw/;

	$message->{'topic'} = $req->{'topic'};
	$message->{'data'} = $response;
	$message->{'data_len'} = length $response;

	$message->send();
}

sub source {
	my $message = shift;

	if (keys(%active_handles) == 0) {
		return 1;
	}

	my $time_limit = time - $timeout_s;
	foreach my $key (keys(%active_handles)) {
		my $req = $active_handles{$key};

		if ($req->{"time"} < $time_limit) {
			$debug->dbg(2, "Timeout for " . $req->{'topic'} . " handle is " . $req->{'handle'} . ", sending empty response\n");

			# Send empty message
			send_response($message, $req, 200, "");

			delete ($active_handles{$key});

			next;
		}

		if (defined $responses{$key}) {
			$debug->dbg(2, "Reply to " . $req->{'topic'} . " handle is " . $req->{'handle'} . "\n");

			# Send stored message
			my $content = $responses{$req->{"handle"}};
			send_response($message, $req, 200, $content);

			delete ($responses{$key});
			delete ($active_handles{$key});

			next;
		}
	}

	return 1;
}

sub update_response {
	my $message = shift;
	my $handle = shift;

	$debug->dbg(2, "Updating response for handle $handle\n");
	$responses{$handle} = $message->{'data'};

	return 1;
}

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	$debug->dbg(2, "Received topic " . $message->{'topic'} . "\n");

	if ($message->{'topic'} =~ /^push\/(.+)/) {
		return update_response($message, $1);
	}

	my $handle = ($message->get_tag_all("handle"))[0];

	if (!defined $handle) {
		$debug->msg(0, "Incoming message did not have a 'push/+'-topic and no handle was found in array message, dropping it\n");
		return 1;
	}

	my %req = (
		"handle" => $handle,
		"topic" => $message->{'topic'},
		"time" => time,
		"id" => ++$req_id
	);

	$active_handles{$handle} = \%req;

	return 1;
}
