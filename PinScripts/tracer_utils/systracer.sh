#!/bin/bash

EXPECTED_ARGS=4
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory}"
    exit 0
fi

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running First Instance of Cupsd (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/systracer.so -o "$1" -- /usr/sbin/cupsd -f -x 0) > "$3/output1.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with First Instance of Cupsd ..."

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running Second Instance of Cupsd (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/systracer.so -o "$2" -- /usr/sbin/cupsd -f -x 0) > "$3/output2.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with Second Instance of Cupsd (blocking call)..."

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done Logging"
