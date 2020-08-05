#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $dbg = { };
bless $dbg, rrr::rrr_helper::rrr_debug;

$dbg->msg(0, "This is my message\n");
$dbg->dbg(1, "This is my message dbg 1\n");
$dbg->err("This is my error message err\n");

sub config {
	my $settings = shift;

	print "perl5 senders: " . $settings->get("senders") . "\n";

	return 1;
}

sub source {
	my $message = shift;

	$message->{'timestamp'} = $message->{'timestamp'};

	$message->send();

	sleep(1);

	return 1;
}

sub process {
	my $message = shift;

	print "perl5 timestamp: " . $message->{'timestamp'} . "\n";
	print "perl5 old topic: " . $message->{'topic'} . "\n";
	$message->{'topic'} .= "/perl5";
	print "perl5 new topic: " . $message->{'topic'} . "\n";

	my @values = (3, 2, 1);
	my $result = 0;

	# Just call all message XSUB functions to make sure they do not crash
	# At the end, clear "tag" tag from array

	$result += $message->push_tag_blob ("tag", "blob", 4);
	$result += $message->push_tag_str ("tag", "str");
	$result += $message->push_tag_h ("tag", 666);
	$result += $message->push_tag_fixp ("tag", 666);
	$result += $message->push_tag ("tag", \@values);

	my @values_result = $message->get_tag_all ("tag");# Returns array of length 7
	$result += $#values_result + 1;

	$result += $message->set_tag_blob ("tag", "blob", 4);
	$result += $message->set_tag_str ("tag", "str");
	$result += $message->set_tag_fixp ("tag", 666);
	$result += $message->set_tag_h ("tag", 1);

	$result += $message->get_tag_all ("tag");	# Returns array of length 1
	$result += ($message->get_tag_all ("tag"))[0];	# Returns the value 1

	$result += $message->clear_tag ("tag");

	if ($result != 19) {
		print ("Result $result<>19\n");
		return 0;
	}

	print "Tag names: " . join(",", $message->get_tag_names ()) . "\n";
	print "Tag counts: " . join(",", $message->get_tag_counts ()) . "\n";

	$message->send();

	$message->clear_array();

	return 1;
}
