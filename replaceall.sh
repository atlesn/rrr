#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/socket\/rrr_msg.h/messages\/rrr_msg.h/g'
