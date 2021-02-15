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

	$body =~ s/\\/\\\\/;
	$body =~ s/"/\\"/;

	my $json = "{
		\"content\": \"$body\",
		\"handle\": $req->{handle},
		\"id\": $req->{id}
}";

#	$message->push_tag_h("http_response_code", $code);
	$message->push_tag_str("http_content_type", "application/json");
	$message->push_tag_str("http_body", $json);

	$message->{'topic'} = $req->{'topic'};

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
