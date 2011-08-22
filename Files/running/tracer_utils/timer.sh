#! /bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory} {timing interval in seconds}"
    exit 0
fi

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Using Candidate PCs To Measure Time"

cat "$3/candidates.tmp" | 
{
j=0
while read line 
do
    currenttime=$(date +"%D %I %M %S %P")
    echo "[$currenttime] Wrote $3/time-$j.time"
    (time /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/timer.so -input "$line" -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &)> "$3/time-$j.time" 2>&1
    j=$((j+1))
    currenttime=$(date +"%D %I %M %S %P")
    echo "[$currenttime] Wrote $3/time-$j.time"
done
}

currenttime=$(date +"%D %I %M %P")
echo "[$currenttime] Done with Measuring Time"
