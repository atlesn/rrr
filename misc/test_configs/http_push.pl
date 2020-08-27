#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $timeout_s = 7;

my %replies = (
	"0" => "No data",
	"1" => "Response for handle one",
	"2" => "Response for handle two"
);

my %active_handles;

sub send_response {
	my $message = shift;
	my $topic = shift;
	my $code = shift;
	my $body = shift;

	$message->clear_array();

	my $response = "";
	if ($code == 200) {
		$response = "HTTP/1.1 200 OK\r\n";
	}
	else {
		$response = "HTTP/1.1 500 Bad Request\r\n";
	}

	if (defined $body && length $body > 0) {
		$response .= "Content-Type: text/html\r\n\r\n";
		$response .= "Content-Length: " . (length $body) . "\r\n\r\n$body";
	}
	else {
		$response .= "\r\n";
	}

	$topic =~ s/request/raw/;

	$message->{'topic'} = $topic;
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
			$debug->dbg(2, "Timeout for " . $req->{'topic'} . " handle is " . $req->{'handle'} . "\n");
			delete ($active_handles{$key});
			next;
		}

		if (rand(10) > 2) {
			$debug->dbg(2, "Reply to " . $req->{'topic'} . " handle is " . $req->{'handle'} . "\n");
			my $content = $replies{$req->{"handle"}};
			if (!defined $content) {
				$content = "No content for this handle\n";
			}
			send_response($message, $req->{'topic'}, 200, $content);
			$message->send();
		}
	}

	return 1;
}

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	my $handle = ($message->get_tag_all("handle"))[0];

	if (!defined $handle) {
		$debug->msg_err("Handle was not defined in request\n");
		send_response($message, $message->{'topic'}, 500);
		return 1;
	}

	my %req = (
		"handle" => $handle,
		"topic" => $message->{'topic'},
		"time" => time
	);

	$active_handles{$handle} = \%req;

	return 1;
}
