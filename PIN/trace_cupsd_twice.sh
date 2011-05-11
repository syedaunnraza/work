#! /bin/bash

EXPECTED_ARGS=1
E_BADARGS=65

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {seconds to run cupsd}"
  exit $E_BADARGS
fi

echo "Tracing Cupsd ... twice for $1 second intervals... "

echo "Running First Instance of Cupsd..."
#/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o trace1.log -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o trace1.log -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
sleep $1

echo "Killing cupsd"
killall cupsd
sleep 5 

echo "Running Second Instance of Cupsd..."
#/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o trace2.log -canary 1 -guard 1  -rdtsc 1 -pid 1 -memory 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o trace2.log -canary 1 -guard 1  -rdtsc 1 -pid 1 -memory 1 -- /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &

sleep $1

echo "Killing cupsd"
killall cupsd
sleep 5

echo "Computing Diffs Without Common Lines"
time (diff --minimal --side-by-side --width=280 --suppress-common-lines trace1.log trace2.log > diff_nocommon.txt)

echo "Computing Diffs With Common Lines"
time (diff --minimal --side-by-side --width=280 trace1.log trace2.log > diff_common.txt)

echo "Done"

