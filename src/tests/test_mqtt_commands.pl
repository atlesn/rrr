#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $active_command = undef;
my @commands = qw/will_1 subscribe_1 will_2 subscribe_2 will_3 subscribe_3/;

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
		$dbg->msg(0, "Unexpected topic '$message->{'topic'}' received from one of the clients. Expected '$expected_topic'.\n");
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

		# Client1 is V3.1.1
		# Client2 is V3.1.1
		# Client3 is V5

		$dbg->msg(1, "-- Test $command\n");

		if ($command eq "will_1") {
			# client2 should produce a retained will publish but not client3
			disconnect($message, "client2", 1);
			disconnect($message, "client3", 1);
		}
		elsif ($command eq "subscribe_1") {
			subscribe($message, "client1", "client2/data/1/+");

			# All messages should arrive
			start_data("client2", "1/1", 1);
			start_data("client2", "1/2", 1);
			start_data("client2", "1/3", 1);
		}
		elsif ($command eq "will_2") {
			# Retained will from client2 should arrive
			subscribe($message, "client1", "client2/will");
			subscribe($message, "client1", "client3/will");

			expect_data("client2/will");
		}
		elsif ($command eq "subscribe_2") {
			unsubscribe($message, "client1", "client2/data/1/+");
			unsubscribe($message, "client1", "client2/will");

			subscribe($message, "client1", "client2/data/2/+");

			# Only second message should arrive
			start_data("client2", "1/4", 0);
			start_data("client2", "2/1", 1);
		}
		elsif ($command eq "will_3") {
			# Non-retained will from client3 should arrive
			disconnect($message, "client3", 1);
			expect_data("client3/will");
		}
		elsif ($command eq "subscribe_3") {
			unsubscribe($message, "client1", "client2/data/2/+");
			unsubscribe($message, "client1", "client3/will");

			subscribe($message, "client3", "client2/data/4/+");
			subscribe($message, "client3", "client2/data/3/+");
			unsubscribe($message, "client3", "client2/data/4/+");

			# Only second message should arrive
			start_data("client2", "4/1", 0);
			start_data("client2", "3/1", 1);
		}
		else {
			$dbg->msg(0, "Bug in test script: Unknown command $command\n");
			return 0
		}

		if (@outgoing_data > 0) {
			$active_command = $command;
		}
	}
	elsif (@expected_data == 0 && @commands == 0 && !defined $active_command && !$fail) {
		# All tests complete
		$dbg->msg(1, "All tests passed\n");
		$message->{'topic'} = "mqtt-ok";
		$message->send();
	}

	return 1;
}

sub disconnect {
	my $message = shift;
	my $client = shift;
	my $with_will = shift;

	start_command($message, $client, "disconnect");
	if ($with_will) {
		$message->push_tag_str ("mqtt_disconnect_with_will", "");
	}
	$message->send();

	return 1;
}

sub subscribe {
	my $message = shift;
	my $client = shift;
	my $topic = shift;

	start_command($message, $client, "subscribe");
	$message->push_tag_str ("mqtt_topic_filter", $topic);
	$message->send();

	$dbg->msg(1, "++ Topic $topic\n");

	return 1;
}

sub unsubscribe {
	my $message = shift;
	my $client = shift;
	my $topic = shift;

	start_command($message, $client, "unsubscribe");
	$message->push_tag_str ("mqtt_topic_filter", $topic);
	$message->send();

	$dbg->msg(1, "++ Topic $topic\n");

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
	else {
		$dbg->msg(1, "== Not expecting result\n");
	}

	$message->send();

	return 1;
}

sub expect_data {
	my $topic = shift;

	push @expected_data, $topic;
	$dbg->msg(1, ">> Expecting result $topic...\n");

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
