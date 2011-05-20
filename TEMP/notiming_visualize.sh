#! /bin/bash

EXPECTED_ARGS=3
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {figures directory}"
    exit 0
fi

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Visualizing Trace For Different Time Slices"

/home/syed/Workspace/Samples/Comparison/notiming_visualization_streaming.py "$1" "$2" "$3/" 

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Done Visualizing Traces For Different Time Slices" 