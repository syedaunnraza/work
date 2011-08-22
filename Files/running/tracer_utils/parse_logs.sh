#! /bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory} {timing interval in seconds}"
    exit 0
fi

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Parsing Log for Timing."
/home/syed/Workspace/Samples/PinScripts/tracing/pin_parse_logs.py "$1" "$2" "$3/candidates.tmp" 50
currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Done Parsing Log for Timing. See $3/candidates.tmp"

