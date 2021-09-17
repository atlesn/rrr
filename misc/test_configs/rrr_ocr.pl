#!/usr/bin/perl -w

package main;

use rrr::rrr_helper;
use rrr::rrr_helper::rrr_message;
use rrr::rrr_helper::rrr_settings;
use rrr::rrr_helper::rrr_debug;
use MIME::Base64;
use Encode;
use utf8;

my $debug = { };
bless $debug, rrr::rrr_helper::rrr_debug;

my $INDEX_HTML_FILENAME = "misc/test_configs/rrr_ocr.html";

open (INDEX, "< $INDEX_HTML_FILENAME") || die("Could not open '$INDEX_HTML_FILENAME': $!\n");
my $INDEX_HTML = do { local $/; <INDEX> };
close INDEX;

my $OCR_CACHE_COUNTER = 0;
my $OCR_CACHE_TIMEOUT_S = 10;
my %OCR_CACHE;

sub ocr_cache_push {
	$OCR_CACHE{$OCR_CACHE_COUNTER++} = {
		"signature" => shift,
		"image" => shift,
		"value" => shift,
		"time" => time
	};
}

sub ocr_cache_maintain {
	foreach my $key (keys(%OCR_CACHE)) {
		if ($OCR_CACHE{$key}->{'time'} < time - $OCR_CACHE_TIMEOUT_S) {
			delete $OCR_CACHE{$key};
		}
	}
}

sub config {
	my $settings = shift;

	return 1;
}

sub send_http_response {
	my $message = shift;
	my $code = shift;
	my $content_type = shift;
	my $body = shift;

	$message->clear_array();

	$message->set_tag_str("http_response_code", $code);
	$message->set_tag_str("http_content_type", $content_type);
	$message->set_tag_str("http_body", $body);

	$message->send();
}

sub send_ocr_response {
	my $message = shift;
	my $value = shift;
	my $signature = shift;

	$message->clear_array();

	utf8::encode($value);
	utf8::encode($signature);

	$signature = decode_base64($signature);

	$message->{'topic'} = "ocr/verify";

	$message->set_tag_str("ocr_value", $value);
	$message->set_tag_blob("ocr_signature", $signature, length $signature);

	$message->send();
}

sub process_http {
	my $message = shift;

	my $endpoint = ($message->get_tag_all("http_endpoint"))[0];

	if ($endpoint eq "/") {
		# Check for OCR command from client
		my $value = ($message->get_tag_all("value"))[0];
		my $signature = ($message->get_tag_all("signature"))[0];

		if (defined $value and defined $signature && length $signature > 0) {
			my $topic_orig = $message->{'topic'};
			send_ocr_response (
				$message,
				$value,
				$signature
			);
			$message->{'topic'} = $topic_orig;
		}

		send_http_response($message, "200", "text/html", $INDEX_HTML);
	}
	elsif ($endpoint eq "/image") {
		# Send a cached image
		my $key = (keys(%OCR_CACHE))[0];
		if (defined $key) {
			#utf8::encode($OCR_CACHE{$key}->{'signature'});
			utf8::encode($OCR_CACHE{$key}->{'value'});
			my $json = 
'{
"image": "' . encode_base64($OCR_CACHE{$key}->{"image"}, "") . '",
"signature": "' . encode_base64($OCR_CACHE{$key}->{"signature"}, "") . '",
"value": "' . encode_base64($OCR_CACHE{$key}->{"value"}, "") . '"
}';
			send_http_response($message, "200", "application/json", $json);
			delete $OCR_CACHE{$key};
		}
		else {
			send_http_response($message, "503", "", "");
		}
	}
	else {
		send_http_response($message, "404", "", "");
	}
}
		
sub process_ocr {
	my $message = shift;

	ocr_cache_push (
		($message->get_tag_all("ocr_signature"))[0],
		($message->get_tag_all("ocr_image"))[0],
		($message->get_tag_all("ocr_value"))[0]
	);
}

sub process {
	my $message = shift;
	
	if ($message->{'topic'} =~ /^httpserver\//) {
		process_http($message);
	}
	elsif ($message->{'topic'} =~ /^ocr\//) {
		process_ocr($message);
	}

	return 1;
}

sub source {
	my $message = shift;

	ocr_cache_maintain();

	return 1;
}
