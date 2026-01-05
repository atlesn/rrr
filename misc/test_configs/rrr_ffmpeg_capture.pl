#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

use Time::Local qw(timegm_posix);

my $FILE_MAX_AGE_S = 300;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

sub source {
	my $message = shift;

	die "Source not implemented";

	return 1;
}

sub process_ffmpeg {
	my $message = shift;

	my $filename = ($message->get_tag_all("ffmpeg_filename"))[0];
	my $directory = ($message->get_tag_all("ffmpeg_directory"))[0];

	chdir($directory) or die "Could not change directory to $directory: %!\n";

	$dbg->msg(1,  "Received report for file $filename in directory $directory topic was '$message->{'topic'}'\n");

	unless (-f "$filename") {
		die "Reported filename '$filename' did not exist\b";
	}

	my $filename_new = $filename;
	$filename_new =~ s/^out-/done-/;

	rename ($filename, $filename_new) or die "Could not rename $filename to $filename_new: $1\n";

	return 1;
}


sub process_directory {
	my $message = shift;

	my @files = $message->get_tag_all("file_name");
	my @paths = $message->get_tag_all("file_path_resolved");

	my $timestamp_limit = time() - $FILE_MAX_AGE_S;

	for (my $i = 0; $i < @files; $i++) {
		my $file = $files[$i];
		my $path = $paths[$i];

		if ($file !~ /(\d\d\d\d)(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z/) {
			$dbg->msg(0, "Could not find timestamp in filename '$file'\n");
			next;
		}

		my $year = $1;
		my $month = $2;
		my $day = $3;
		my $hour = $4;
		my $minute = $5;
		my $second = $6;

		my $timestamp = timegm_posix($second, $minute, $hour, $day, $month - 1, $year - 1900);

		if ($timestamp < $timestamp_limit) {
			$dbg->msg(1, "File '$file'->'$path' is older than $FILE_MAX_AGE_S seconds, deleting\n");
			unless (unlink $path) {
				$dbg->msg(0, "Warning: Could not unlink file '$path': $!\n");
			}
		}
	}

	return 1;
}
