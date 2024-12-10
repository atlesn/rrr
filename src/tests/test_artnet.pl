#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

my $TOPIC_RESULT = "test-result";
my $TOPIC_ARTNET_CMD = "artnet-command";

sub source {
	my $message = shift;

#	$message->{'topic'} = $TOPIC_RESULT;
#	$message->send();

	$dbg->msg(1, "Send ArtNet fade command\n");

	$message->{'topic'} = $TOPIC_ARTNET_CMD;
	$message->push_tag("artnet_cmd", "fade");
	$message->push_tag("artnet_universe", 4);
	$message->push_tag("artnet_dmx_channel", 4);
	$message->push_tag("artnet_dmx_data", "aaaa");
	$message->send();

	return 1;
}

sub process {
	my $message = shift;

	return 1;
}
