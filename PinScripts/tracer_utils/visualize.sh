#! /bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory} {timing interval in seconds}"
    exit 0
fi

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Visualizing Trace With Timing Files"

FILES="$3/*.time"
#echo $FILES
/home/syed/Workspace/Samples/Comparison/diff_plotter_timing.py "$3/diff.log" "$4/" $FILES

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Done Visualizing Trace With Timing Files" 