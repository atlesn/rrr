#!/usr/bin/env bash

set -e

source ./testlib.sh
source ../../variables.sh

gpio_dev=$(./get_gpio_device.sh)

if [ "x$gpio_dev" = "x" ]; then
	echo "GPIO mockup device not found, skipping tests"
	exit 0
fi

ensure_config test_gpio.conf gpio_chip "/dev/$gpio_dev"
ensure_config test_gpio.conf gpio_chip_debugfs "/sys/kernel/debug/gpio-mockup/$gpio_dev"

do_test_simple test_gpio.conf
