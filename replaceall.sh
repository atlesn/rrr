#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/receive_rrr_msg_msg/receive_rrr_message/g'
