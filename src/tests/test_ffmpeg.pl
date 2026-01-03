#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	die "Source not implemented";

	return 1;
}

my $state = 0;

sub process {
	my $message = shift;

	my $filename = ($message->get_tag_all("ffmpeg_filename"))[0];
	my $directory = ($message->get_tag_all("ffmpeg_directory"))[0];

	die "Directory missing\n" unless defined $directory;
	die "Directory was not /tmp\n" unless $directory eq "/tmp";

	chdir($directory) or die "Could not change directory to $directory: %!\n";

	die "Filename missing\n" unless defined $filename;
	die "Filename format error\n" unless $filename =~ /^out-\d\d\d\d\d\d\d\dT\d\d\d\d\d\dZ\.mp4$/;

	$dbg->msg(1,  "Received report for file $filename topic was '$message->{'topic'}'\n");

	unless (-f "$filename") {
		die "Reported filename '$filename' did not exist\b";
	}

	unlink $filename or die "Could not unlink $filename: $!\n";

	$state++;

	if ($state == 2) {
		$dbg->msg(1, "All messages received, sending notification message\n");
		$message->{'topic'} = "success";
		$message->clear_array();
		$message->send();
	}
	elsif ($state > 2) {
		die "Too many messages received\b";
	}

	return 1;
}
