#!/usr/bin/env bash

gpio_dev=$(gpiodetect | grep gpio-mockup | awk '{print $1; exit}')

if [ "x$gpio_dev" = "x" ]; then
	exit 0
fi

if [ ! -c "/dev/$gpio_dev" ]; then
	exit 1
fi

echo $gpio_dev
