#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my %results;

my $step = 0;

sub source_client {
	my $message = shift;

	if ($step == 0) {
		$message->{'topic'} = 'request';
		$message->push_tag_str('http_method', 'get');
		$message->push_tag_str('http_endpoint', '/bodyless');
		$message->push_tag_str('http_body', '');
		$message->send();
	}
	elsif ($step == 1) {
		$message->{'topic'} = 'request';
		$message->push_tag_str('http_method', 'put');
		$message->push_tag_str('http_endpoint', '/bodiful');
		$message->push_tag_str('http_body', "body" x 786432);
		$message->send();
	}
	else {
		# Done
	}

	$step++;

	return 1;
}

my $client_ok = 0;

sub process_client {
	my $message = shift;

	my $body = ($message->get_tag_all("http_body"))[0];
	my $code = ($message->get_tag_all("http_response_code"))[0];

	if ($step == 1) {
		die "Incorrect response code" unless $code == 204;
		die "Double bodyless" if $client_ok & 1;
		die "Unexpected body" if defined $body;
		$client_ok |= 1;
	}
	elsif ($step == 2) {
		die "Incorrect response code" unless $code == 200;
		die "Double body" if $client_ok & 2;
		die "Expected body" unless defined $body;
		die "Incorrect body" unless $body eq "body" x 786432;
		$client_ok |= 2;
	}
	else {
		die "Unexpected response";
	}

	if ($client_ok == 3) {
		$message->clear_array();
		$message->{'topic'} = 'success';
		$message->send();
	}

	return 1;
}

my $server_ok = 0;

sub process_server {
	my $message = shift;

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];
	my $body = ($message->get_tag_all("http_body"))[0];
	my $method = ($message->get_tag_all("http_method"))[0];

	if ($endpoint eq "/bodyless") {
		die "Double bodyless" if $server_ok & 1;
		die "Body in bodyless" if defined $body;
		die "Method was not GET" unless $method eq "GET";
		$message->push_tag_h("http_response_code", 204);
		$server_ok |= 1;
	}
	elsif ($endpoint eq "/bodiful") {
		die "Double body" if $server_ok & 2;
		die "No body in bodiful" unless defined $body;
		die "Method was not PUT" unless $method eq "PUT";
		die "Incorrect body" unless $body eq "body" x 786432;
		$message->push_tag_h("http_response_code", 200);
		$server_ok |= 2;
	}
	else {
		die "Unknown endpoint";
	}

	$message->send();

	return 1;
}
