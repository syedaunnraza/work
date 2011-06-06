#!/bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory} {timing interval in seconds}"
    exit 0
fi


echo ""
currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Logging Cupsd Traces ... Twice for $5 second intervals"
    
currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Running First Instance of Cupsd ($5 seconds)..."
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -print_func 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
sleep $5

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Killing cupsd"
killall cupsd
sleep 5

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Running Second Instance of Cupsd ($5 seconds)..."
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
sleep $5

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Killing cupsd"
killall cupsd
sleep 5

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Done Logging"
