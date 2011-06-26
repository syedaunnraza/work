#! /bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder w/o '/'} {figures directory w/o '/'} {timing interval in seconds}"
    exit 0
fi

echo ""
currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Analysis Scripts are Starting"

(sysctl kernel.randomize_va_space=0) > /dev/null

/home/syed/Workspace/Samples/PinScripts/tracer_utils/logger.sh $1 $2 $3 $4 $5
#/home/syed/Workspace/Samples/PinScripts/tracer_utils/parse_logs.sh $1 $2 $3 $4 $5
#/home/syed/Workspace/Samples/PinScripts/tracer_utils/timer.sh $1 $2 $3 $4 $5
/home/syed/Workspace/Samples/PinScripts/tracer_utils/differ.sh $1 $2 $3 $4 -1
#/home/syed/Workspace/Samples/PinScripts/tracer_utils/visualize.sh $1 $2 $3 $4 $5
/home/syed/Workspace/Samples/PinScripts/tracer_utils/notiming_visualize.sh "$3/diff.log" "$4/"

echo ""
currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Analysis Scripts are Done"
echo