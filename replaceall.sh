#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/rrr_message/rrr_msg_msg/g'
