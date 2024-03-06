#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $state = 0;

sub source {
	my $message = shift;

	if ($state == 0) {
		$message->push_tag_str("artnet_cmd", "set");

		$debug->msg(1, "Set dark\n");

		$message->send();
	}
	else {
		$message->push_tag_str("artnet_cmd", "fade");
		$message->push_tag_str("artnet_universe", "0");
		$message->push_tag_str("artnet_dmx_channel", "0");

		if ($state % 2 == 0)  {
			$debug->msg(1, "Set green\n");
			$message->push_tag_blob("artnet_dmx_data", pack('C*', 0, 255, 0, 0), 4);
			$message->push_tag_str("artnet_fade_speed", "1");
		}
		else {
			$debug->msg(1, "Set white\n");
			$message->push_tag_blob("artnet_dmx_data", pack('C*', 0, 0, 0, 255), 4);
			$message->push_tag_str("artnet_fade_speed", "10");
		}

		$message->send();
	}

	$state++;

	return 1;
}
