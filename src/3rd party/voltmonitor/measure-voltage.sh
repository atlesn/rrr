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

# Usage: ./measure-voltage path_to_working_dir [path_to_storage_dir]
# If 'path_to_storage_dir' is not given the 'working_dir' is used for storage.
# The 'working_dir' must contain all executable files.

# This script depends on:
# - binary of 'checkvoltage' for your CPU architecture, either one
#      of the provided ones for ARM or i386, or one you have to compile
#      by yourself out of 'checkvoltage.c' (see README)
# - gnuplot
# - imagemagick
# - mutt
# - bc
# - apache2 (if you want to access the produced images via the net)
# - sqlite3
# - sed


# check for command line arguments, on errors throw usage message or errors
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
        echo "Usage: $0 path_to_working_dir [path_to_storage_dir]"
	echo "If 'storage_dir' is not given the 'working_dir' is used for storage"
        exit 1
elif [ $# == 1 ]; then
	workdir=$1
	storedir="$workdir"
elif [ ! -w "$1" ] || [ ! -w "$2" ]; then
        echo -e "\n'$1' or '$2' is not writable. Check your file permissions:"
	ls -ald $1
	ls -ald $2
	echo
	exit 1
else
	workdir=$1
	storedir=$2
fi

# set the measuring interval (in seconds)
interval=600

# if you want to have some logs set 'logging' to 1
logging=0
logfile=$storedir/measure-voltage.log

# switch to the given dir
cd $workdir

# create SQLite database if not yet present
if [ ! -f $storedir/voltages.db ]; then
        sqlite3 $storedir/voltages.db "CREATE TABLE voltages (ID INTEGER PRIMARY KEY, DATE TEXT, V NUMERIC);"
fi

# flags and variables for monitoring:
# flagVM:		USB voltmeter present/absent
# flagUV:		undervoltage flag
# flagCUV:		critical undervoltage flag
# flagOV:		overvoltage flag
# flag COV:		critical overvoltage flag
# flagload:		electric load connected/disconnected
function resetflags() {
        flagVM=1
        flagUV=0
        flagCUV=0
        flagOV=0
        flagCOV=0
        flagload=0
}
resetflags

# voltage boundaries
UV=22.6		# undervoltage
CUV=21.6	# critical undervoltage
OV=28.8		# overvoltage
COV=29.5	# critical overvoltage

# other variables
mail=""  # put in here your mail address
mailsubject="Message from USBVoltmeter"
lastmail=0
mailtype=0

# declare some functions

function sendmail() {
        if [ "$lastmail" != "$mailtype" ]; then
                echo "$1" | mutt -s "$mailsubject" -- "$mail"
                lastmail=$mailtype
        fi
}

function shutdownserver() {
	# not yet implemented
	echo "sudo poweroff"
}

function electricload() {
	if [ "$flagCOV" == 1 ]; then
		flagload=1
	elif [ "$flagOV" == 0 ]; then
		flagload=0
	fi
}

function sqlitequeries() {
	now=$(date +%d/%m/%Y)
	day1=$(date +%d/%m/%Y -d "1 day ago")
	day2=$(date +%d/%m/%Y -d "2 days ago")

	nowstart=$now"-00:00:00"
	nowend=$now"-23:59:59"
	day1start=$day1"-00:00:00"
	day1end=$day1"-23:59:59"
	day2start=$day2"-00:00:00"
	day2end=$day2"-23:59:59"

	sqlite3 -column $storedir/voltages.db "SELECT date,v FROM voltages WHERE date > '$nowstart' AND date < '$nowend'" > $storedir/plotday1.txt
	sqlite3 -column $storedir/voltages.db "SELECT date,v FROM voltages WHERE date > '$day1start' AND date < '$day1end'" > $storedir/plotday2.txt
	sqlite3 -column $storedir/voltages.db "SELECT date,v FROM voltages WHERE date > '$day2start' AND date < '$day2end'" > $storedir/plotday3.txt

	sed -i -e 's@'"$day1"'@'"$now"'@g' $storedir/plotday2.txt
	sed -i -e 's@'"$day2"'@'"$now"'@g' $storedir/plotday3.txt

	sqlite3 -column $storedir/voltages.db "SELECT date,v FROM voltages LIMIT 432 OFFSET (SELECT COUNT(*) FROM voltages)-432;" > $storedir/short.txt
	sqlite3 -column $storedir/voltages.db "SELECT date,v FROM voltages;" > $storedir/full.txt
}

function plotdata() {
        cat $storedir/short.txt | ./plotvoltage.pg > $storedir/voltage_short.png
        cat $storedir/full.txt | ./plotvoltage.pg > $storedir/voltage_full.png
        ./plotmultivoltage.pg > $storedir/voltage_compare.png

	# write some text into the images
	convert $storedir/voltage_short.png -pointsize 12 -draw "text 100,95 'created `date +%A,%n%d.%m.%Y' at '%H:%M`' text 100,120 'last measured voltage: $voltage' " $storedir/voltage_short.png
	convert $storedir/voltage_full.png -pointsize 12 -draw "text 100,95 'created `date +%A,%n%d.%m.%Y' at '%H:%M`' text 100,120 'last measured voltage: $voltage' " $storedir/voltage_full.png
	convert $storedir/voltage_compare.png -pointsize 12 -draw "text 100,95 'created `date +%A,%n%d.%m.%Y' at '%H:%M`' text 100,120 'last measured voltage: $voltage' " $storedir/voltage_compare.png

	# move the images to the a web server folder
        sudo mv $storedir/voltage_short.png /var/www/voltages/voltage_short.png
        sudo mv $storedir/voltage_full.png /var/www/voltages/voltage_full.png
        sudo mv $storedir/voltage_compare.png /var/www/voltages/voltage_compare.png
}

function sleepinterval() {
	# wait until next interval. Modulo is used to get the number of seconds to wait.
	# quite sophisticated idea, isn't it? ;-)
        duration=$(expr $interval - $(expr $(date +%s) % $interval))
        sleep $duration
}


# wait for 1st interval
sleepinterval

while [ $flagVM -eq 1 ]; do

# voltmeter query
# This is the place where you could use the voltmeter simulator
#	voltage=$(./voltmeter_sim.sh)
	voltage=$(sudo ./checkvoltage)

# does the voltmeter report an error? That is verfied by checking its answer on digits.
	if [[ ! $voltage =~ ^[+-]?[0-9]+\.?[0-9]*$ ]]; then
		flagVM=0
        	sendmail "no sensor: $voltage"

	else

# make the entry in our storage file
		date=$(date '+%d/%m/%Y-%H:%M:%S')
		sqlite3 $storedir/voltages.db "INSERT INTO voltages (DATE,V) VALUES ('$date','$voltage');"

# get the SQLite data
		sqlitequeries

# make a nice picture out of the data
		plotdata

# voltage monitoring
		if (( $(bc <<< "$voltage < $CUV") == 1 )); then
		# send a warning mail, set flag for script termination, shutdown computer
			flagCUV=1
			flagVM=0
			mailtype=1
			sendmail "Server will be shut down because of critical undervoltage"
			shutdownserver

		elif (( $(bc <<< "$voltage < $UV") == 1 )); then
		# send a warning mail
			flagUV=1
                	mailtype=2
			sendmail "Warning: undervoltage. Prepare for server shutdown."

		elif (( $(bc <<< "$voltage > $COV") == 1 )); then
		# send a warning mail, switch on electric load unless it isn't on
			flagCOV=1
                	mailtype=3
			sendmail "Warning: critical overvoltage. Batteries are suffering!!"
			electricload

		elif (( $(bc <<< "$voltage > $OV") == 1 )); then
		# send a warning mail
			flagOV=1
                	mailtype=4
                	sendmail "Warning: overvoltage. Batteries will suffer soon!"
		else
		# send info mail, switch off electric load unless it isn't off
                	resetflags
                	mailtype=5
                	sendmail "A-OK! voltage = $voltage"
                	electricload
		fi
	fi

	# write the log if it is wanted
	if [ "$logging" -gt 0 ]; then
		echo "$date - $voltage | flags: VM:$flagVM, CUV:$flagCUV, UV:$flagUV, OV:$flagOV, COV:$flagCOV, load:$flagload, mail:$lastmail" >> $logfile
	fi

	# wait until next interval.
	sleepinterval

done
