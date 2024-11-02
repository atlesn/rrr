#!/bin/sh

find src \( -type d -name .git -prune \) -o -type f -print0 | xargs -0 sed -i 's/rrr_array_new_message_from_collection/rrr_array_new_message_from_array/g'
