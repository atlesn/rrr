#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $active_command = undef;
my @commands = qw/subscribe_1/;

my @outgoing_data;
my @expected_data;
my $fail = 0;

sub process {
	my $message = shift;

	my $expected_topic = shift @expected_data;

	if (!defined $expected_topic) {
		$dbg->msg(0, "Received an unexpected message from one of the clients\n");
		$fail = 1;
		return 1;
	}

	$dbg->msg(1, "<< Result $message->{'topic'}\n");
	if ($expected_topic ne $message->{'topic'}) {
		$dbg->msg(0, "Unexpected topic '$message->{'topic'}' received from one of the clients\n");
		$fail = 1;
		return 1;
	}
	$dbg->msg(1, "== OK\n");

	if (@expected_data == 0) {
		$active_command = undef;
	}

	return 1;
}

sub source {
	my $message = shift;

	while (@outgoing_data > 0) {
		send_data($message);
	}

	if (!defined $active_command and @commands > 0) {
		my $command = shift @commands;

		if ($command eq "subscribe_1") {
			# 1. Tell client1 to subscribe to topics client2/#
			start_command($message, "client1", "subscribe");
			$message->push_tag_str ("mqtt_topic_filter", "client2/#");
			$message->send();

			# 2. Send a message to client 2 with a topic matching
			#    the subscription.
			start_data("client2", "data1", 1);
			start_data("client2", "data2", 1);
			start_data("client2", "data3", 1);
		}
		else {
			$dbg->msg(0, "Bug in test script: Unknown command $command\n");
			return 0
		}

		$active_command = $command;
	}
	elsif (@expected_data == 0 && @commands == 0 && !defined $active_command && !$fail) {
		# All tests complete
		$dbg->msg(1, "All tests passed\n");
		$message->{'topic'} = "mqtt-ok";
		$message->send();
	}

	return 1;
}

sub send_data {
	my $message = shift;

	my $data = shift @outgoing_data;

	$message->clear_array();
	$message->{'topic'} = $data->{'topic'};

	$dbg->msg(1, ">> [$data->{'client'}] Data $data->{'topic'}\n");

	if ($data->{'expect_return'}) {
		push @expected_data, $message->{'topic'};
		$dbg->msg(1, ">> Expecting result...\n");
	}

	$message->send();

	return 1;
}

sub start_data {
	my $client = shift;
	my $topic = shift;
	my $expect_return = shift;

	my %data = (
		"client" => $client,
		"topic" => "$client/data/$topic",
		"expect_return" => $expect_return
	);

	push @outgoing_data, \%data;

	return 1;
}

sub start_command {
	my $message = shift;
	my $client = shift;
	my $command = shift;

	$message->clear_array();
	$message->{'topic'} = "$client/command";

	$message->push_tag_str ("mqtt_command", $command);

	$dbg->msg(1, ">> [$client] Command $command\n");

	return 1;
}
