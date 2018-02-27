#!/bin/bash

# voltage monitor and plotter for single channel USBVoltmeter from
#    http://digital-measure.com

# Copyright (C) April 2015 by Frank Lassowski (flassowski@gmx.de)

# This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# In case your voltmeter is not ready you can use this simulator which
# echoes random voltages between adjustable borders

low=23
high=29

a=$(expr $low - 1)
b=$(expr $high - $a)

num=$[($RANDOM % $b)+$a]
digit1=$[($RANDOM % 9)]
digit2=$[($RANDOM % 9)]

echo $num"."$digit1$digit2
