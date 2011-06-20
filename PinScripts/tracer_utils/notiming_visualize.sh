#! /bin/bash

EXPECTED_ARGS=2
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {diff file} {figures prefix}"
    exit 0
fi

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Visualizing Trace For Different Time Slices"

#/home/syed/Workspace/Samples/Comparison/notiming_visualization_streaming.py "$1" "$2" "$3/" 
(/home/syed/Workspace/Samples/PinScripts/tracing/diff_plotter.py "$1" "$2") > "$2/diff_stats.txt"

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done Visualizing Traces For Different Time Slices" 