#!/bin/sh

lcov -c -d . --output-file main_coverage.info
genhtml main_coverage.info --output-directory lcov

