#!/bin/sh

set -x

PIDS=""

sudo pkt-gen -i netmap:pipe{1 -f tx -s 10.0.0.1:7000-10.0.0.1:7010 -d 10.0.0.1:8000-10.0.0.1:8004 2>&1 > /dev/null &
PIDS="$PIDS $!"
sleep 0.5
sudo ./fe -i netmap:pipe}1 -i netmap:pipe{2 -i netmap:pipe{3 -p 8000 -p 8001 &
PIDS="$PIDS $!"
sleep 0.5
sudo ./swap -i netmap:pipe}2 -i netmap:pipe{4 &
PIDS="$PIDS $!"
sleep 0.5
sudo ./swap -i netmap:pipe}3 -i netmap:pipe{5 &
PIDS="$PIDS $!"
sleep 0.5
sudo ./sink -i netmap:pipe}4 -p 7000 &
PIDS="$PIDS $!"
sleep 0.5
sudo ./sink -i netmap:pipe}5 -p 7001 &
PIDS="$PIDS $!"
sleep 0.5

echo $PIDS > pids
