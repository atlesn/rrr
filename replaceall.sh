#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/ip\/message/message_holder\/message/g'
