#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/rrr_msg_msg_broker/rrr_message_broker/g'
