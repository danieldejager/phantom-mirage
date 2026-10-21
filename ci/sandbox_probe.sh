#!/bin/sh
# Script-port probe for the #16 CI step: reports what the script may do,
# then stays alive so CI can read its /proc/<pid>/status from outside.
t() { if eval "$2" >/dev/null 2>&1; then echo "$1=ok"; else echo "$1=denied"; fi; }
t write_tmp   'touch /tmp/hdsb/tmp/escape'
t write_allow 'touch /tmp/hdsb/rw/allowed'
t list_home   'ls /root || ls /home'
t read_etc    'test -r /etc/passwd && cat /etc/passwd'
t proc_host   'ls /proc/1'
t unshare     'unshare -U true'
echo READY
sleep 4
