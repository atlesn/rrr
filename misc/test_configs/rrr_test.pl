#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;

my $global_settings = undef;

sub config {
	# Get the rrr_settings-object. Has get(key) and set(key,value) methods.
	my $settings = shift;

	# If needed, save the settings object
	$global_settings = $settings;

	# Custom settings from the configuration file must be read to avoid warning messages
	# print "my_custom_setting is: " . $settings->get("my_custom_setting") . "\n";

	# Set a custom setting
	$settings->set("my_new_setting", "5");

	return 1;
}

sub source {
	# Receive a template message
	my $message = shift;

	# Do some modifications
	#$message->{'timestamp'} = $message->{'timestamp'} - $global_settings->get("my_custom_setting");

	$message->{'topic'} = "aaa/bbb/ccc";

	print "source: new timestamp of message is: " . $message->{'timestamp'} . "\n";
#	print "array ptr: " . $message->{'rrr_array_ptr'} . "\n";

	$message->set_tag_str("my_tag", "my_string");
	$message->set_tag_str("my_tag", "my_string");
	$message->set_tag_str("my_tag", "my_string");
	$message->push_tag_str("my_tag", "my_string 2");
	$message->push_tag_str("my_tag", "my_string 3");
	$message->push_tag_str("my_tag", "my_string 4");

	# Should be 4 now

	my @values = $message->get_tag("my_tag");

	print "getting tag at: " . $message->get_tag_at("my_tag", 1) . "\n";
	print "getting tag: @values\n";

	my $blob = "aaaaaaaaa";
	$message->push_tag_blob("my_blob", $blob, length $blob);

	my @array = ("4", "3", "2");
	my $bin = pack 'H*', 'ab6501d0e75f12020c14da1545a5';

	$message->push_tag("my_auto_1", "aaa");
	$message->push_tag("my_auto_2", 2222);
	$message->push_tag("my_auto_3", -2222);
	$message->push_tag("my_auto_4", \@array);
	$message->push_tag("my_auto_4", \@array);
	$message->push_tag("my_auto_5_bin", $bin);
	$message->push_tag("my_auto_6", 3.141592);
	$message->push_tag_fixp("my_fixp_1", "16#ad4e65.eeee");
	$message->push_tag_fixp("my_fixp_2", "10#3.141592");
	$message->push_tag_fixp("my_fixp_3", 3.141592);
	$message->push_tag_fixp("my_fixp_4", 6666);
	$message->push_tag_blob("my_blob", $bin, length $bin);

#	$message->send();

	my $fixp = $message->get_tag_at("my_fixp_4", 0);
	print "my_fixp_4: $fixp\n";

	$message->clear_array();
	#$message->{'timestamp'} += 1000000;
#	$message->send();

	$message->ip_set("127.0.0.1", 456);
	my ($ip, $port) = $message->ip_get();
	print "IP: $ip PORT: $port\n";

	$message->ip_set("20a0:55::4", 456);
	my ($ip6, $port6) = $message->ip_get();
	print "IP: $ip6 PORT: $port6\n";

	$message->ip_clear();
	my ($ip_cleared, $port_cleared) = $message->ip_get();

	print "After clear: " . (defined $ip_cleared ? $ip_cleared : "undefined") . "\n";

	my @values = (1,2,3);

	$message->clear_array();

	$message->set_tag_blob ("tag", "blob", 4);
	$message->set_tag_str ("tag", "str");
	$message->set_tag_h ("tag", \@values);
	$message->set_tag_fixp ("tag", 666);
	$message->get_tag ("tag");
	$message->push_tag_blob ("tag", "blob", 4);
	$message->push_tag_str ("tag", "str");
	$message->push_tag_h ("", 666);
	$message->push_tag_fixp ("tag", 666);
	$message->push_tag ("tag", \@values);
	$message->push_tag ("a", \@values);
	$message->push_tag ("b", \@values);
	$message->push_tag ("c", \@values);
	
	print "Number 666: " . $message->get_tag_at ("", 0) . "\n";
	print "Multiple values: " . join(",", $message->get_tag ('tag')) . "\n";
	print "Tag names: " . join(",", $message->get_tag_names ()) . "\n";
	print "Tag counts: " . join(",", $message->get_tag_counts ()) . "\n";

	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	# Do some modifications to the message
	#$message->{'timestamp'} = $message->{'timestamp'} - $global_settings->get("my_custom_setting");

	#print "process: new timestamp of message is: " . $message->{'timestamp'} . "\n";

	#my $message_text = get_from_tag_or_default($message, "log_message", "no message");
	#chomp $message_text;

	#print "log prefix: '" . get_from_tag_or_default($message, "log_prefix", "no prefix") . "'\n";
	#print "log message: '$message_text'\n";

	#my @numbers = (0, 1, 2, 3, 4444444444444444444444444444, -5);

	# Create an array in the message and write some values
	#push_tag_str($message, "value_a", "This is the 'a' value");
	#push_tag_h($message, "value_number", 12345);
	#push_tag_array($message, "value_numbers", \@numbers, "h");
	#push_tag_blob($message, "value_blob", "abcd");

	$message->{'ip_so_type'} = "tcp";

	# This can be used to duplicate a message if called multiple times
	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

