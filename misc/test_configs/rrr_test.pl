#!/usr/bin/perl -w

package main;

use Socket qw(:DEFAULT :crlf inet_ntop);
use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

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

	sleep(2);

	return 1;
}

sub source {
	# Receive a template message
	my $message = shift;

	# Do some modifications
	#$message->{'timestamp'} = $message->{'timestamp'} - $global_settings->get("my_custom_setting");

	$message->{'topic'} = "aaa/bbb/ccc";

	$debug->msg(1, "Sourcing message\n");

	$debug->msg(1, "source: new timestamp of message is: " . $message->{'timestamp'} . "\n");
#	print "array ptr: " . $message->{'rrr_array_ptr'} . "\n";

	$message->set_tag_str("my_tag", "my_string");
	$message->set_tag_str("my_tag", "my_string");
	$message->set_tag_str("my_tag", "my_string");
	$message->push_tag_str("my_tag", "my_string 2");
	$message->push_tag_str("my_tag", "my_string 3");
	$message->push_tag_str("my_tag", "my_string 4");

	# Should be 4 now

	my @values = $message->get_tag_all("my_tag");

	$debug->msg(1, "getting tag at: " . $values[1] . "\n");
	$debug->msg(1, "getting tag: @values\n");

	my $blob = "aaaaaaaaa";
	$message->push_tag_blob("my_blob", $blob, length $blob);

	my @array = ("4", "3", "2");
	my $bin = pack 'H*', 'ab6501d0e75f12020c14da1545a5';

	$message->push_tag("my_auto_1", "aaa");
	$message->push_tag("my_auto_2", 2222);
	$message->push_tag("my_auto_3", -2222);
	$message->push_tag("my_auto_4", \@array);
	$message->push_tag("my_auto_4", \@array);
	sleep(0.005);
	$message->push_tag("my_auto_5_bin", $bin);
	$message->push_tag("my_auto_6", 3.141592);
	$message->push_tag_fixp("my_fixp_1", "16#ad4e65.eeee");
	$message->push_tag_fixp("my_fixp_pi_10", "10#3.141592");
	$message->push_tag_fixp("my_fixp_pi_double", 3.141592 + 0);
	$message->push_tag_fixp("my_fixp_4", 0x29b - 1);
	$message->push_tag_fixp("my_fixp_5", "16#a");
	sleep(0.005);
	$message->push_tag_fixp("my_fixp_6", "10#10");
	$message->push_tag_fixp("my_fixp_7", "16#0.8");
	$message->push_tag_fixp("my_fixp_8", "10#0.5");
	$message->push_tag_fixp("my_fixp_9", -2);
	$message->push_tag_blob("my_blob", $bin, length $bin);

#	$message->send();

	$message->set_tag_fixp("my_fixp_5", ($message->get_tag_all("my_fixp_5"))[0]);

	my $fixp_5 = ($message->get_tag_all("my_fixp_5"))[0];
	my $fixp_6 = ($message->get_tag_all("my_fixp_6"))[0];

	$debug->msg(1, "my_fixp_5 $fixp_5 == my_fixp_6 $fixp_6\n");

	my $fixp_7 = ($message->get_tag_all("my_fixp_7"))[0];
	my $fixp_8 = ($message->get_tag_all("my_fixp_8"))[0];

	$debug->msg(1, "my_fixp_7 $fixp_7 == my_fixp_8 $fixp_8\n");
	
	my $fixp_9 = ($message->get_tag_all("my_fixp_9"))[0];
	$debug->msg(1, "my_fixp_9 $fixp_9\n");

	my $fixp_pi_10 = ($message->get_tag_all("my_fixp_pi_10"))[0];
	my $fixp_pi_double = ($message->get_tag_all("my_fixp_pi_double"))[0];

	$debug->msg(1, "my_fixp_pi_10: $fixp_pi_10, my_fixp_pi_double: $fixp_pi_double\n");

	my $fixp = ($message->get_tag_all("my_fixp_4"))[0];
	$debug->msg(1, "my_fixp_4: $fixp\n");

	$message->clear_array();
	#$message->{'timestamp'} += 1000000;
#	$message->send();

	$message->ip_set("127.0.0.1", 456);
	my ($ip, $port) = $message->ip_get();
	$debug->msg(1, "IP: $ip PORT: $port\n");

	$message->ip_set("20a0:55::4", 456);
	my ($ip6, $port6) = $message->ip_get();
	$debug->msg(1, "IP: $ip6 PORT: $port6\n");

	$message->ip_clear();
	my ($ip_cleared, $port_cleared) = $message->ip_get();

	$debug->msg(1, "After clear: " . (defined $ip_cleared ? $ip_cleared : "undefined") . "\n");

	@values = (1,2,3);

	$message->clear_array();

	$message->set_tag_blob ("tag", "blob", 4);
	$message->set_tag_str ("tag", "str");
	$message->set_tag_h ("tag", \@values);
	$message->set_tag_fixp ("tag", 666);
	$message->get_tag_all ("tag");
	$message->push_tag_blob ("tag", "blob", 4);
	$message->push_tag_str ("tag", "str");
	$message->push_tag_h ("", 666);
	$message->push_tag_fixp ("tag", 666);
	$message->push_tag ("tag", \@values);
	$message->push_tag ("a", \@values);
	$message->push_tag ("b", \@values);
	$message->push_tag ("c", \@values);

	$debug->msg(1, "Get a position: " . join (",", $message->get_position(2)) . "\n");
	$debug->msg(1, "Array position count: " . $message->count_positions() . "\n");
	$debug->msg(1, "Number 666: " . ($message->get_tag_all(""))[0] . "\n");
	$debug->msg(1, "Multiple values: " . join(",", $message->get_tag_all("tag")) . "\n");
	$debug->msg(1, "Tag names: " . join(",", $message->get_tag_names ()) . "\n");
	$debug->msg(1, "Tag counts: " . join(",", $message->get_tag_counts ()) . "\n");

	$message->send();

	# Return 1 for success and 0 for error
	return 1;
}

my $total_processed = 0;

sub process {
	# Get a message from senders of the perl5 instance
	my $message = shift;

	if (length $message->{'ip_addr'} == 0) {
		# No IP-data
	}
	elsif (length $message->{'ip_addr'} == 28) {
		my ($port, $ip_address) = unpack_sockaddr_in6 $message->{'ip_addr'};
		my $ip_str = inet_ntop AF_INET6, $ip_address; 
		print "Source: $ip_str:$port type " . $message->{'ip_so_type'} . "\n";
	}
	else {
		my ($port, $ip_address) = unpack_sockaddr_in $message->{'ip_addr'};
		my $ip_str = inet_ntop AF_INET, $ip_address; 
		print "Source: $ip_str:$port type " . $message->{'ip_so_type'} . "\n";
	}

	# Create an array in the message and write some values
	#push_tag_str($message, "value_a", "This is the 'a' value");
	#push_tag_h($message, "value_number", 12345);
	#push_tag_blob($message, "value_blob", "abcd");

	# This can be used to duplicate a message if called multiple times
	$message->send();

#	sleep(($$ % 2) / 10);

#	print "Total processed for worker $$: " . (++$total_processed) . "\n";

	# Return 1 for success and 0 for error
	return 1;
}

