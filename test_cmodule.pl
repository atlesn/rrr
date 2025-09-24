#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use bytes;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my @phrase = qw/THIS IS A VERY LONG TEST PHRASE POSSIBLY USING MULTIPLE LINES/;
my $phrase_pos = -1;

sub source {
	my $message = shift;

	if ($phrase_pos == -1) {
		foreach my $word (@phrase) {
			$message->push_tag_str("phrase_full_word", $word);
		}
		$message->send();
		$phrase_pos = 0;
		return 1;
	}

	if ($phrase_pos >= @phrase) {
		$phrase_pos = -1;
		return 1;
	}

	my $phrase_step = int(rand(3)) + 1;

	$message->clear_array();
	for (my $i = 0; $i < $phrase_step && $phrase_pos < @phrase; $i++) {
		my $word = $phrase[$phrase_pos];
		$message->push_tag_str("phrase_chunk_word", $word);
		$phrase_pos++;
	}
	$message->send();

	return 1;
}

sub process {
	my $message = shift;


	return 1;
}
