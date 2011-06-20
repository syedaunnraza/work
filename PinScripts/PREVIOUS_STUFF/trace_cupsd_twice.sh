#! /bin/bash

EXPECTED_ARGS=1
E_BADARGS=65

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {seconds to run cupsd}"
  exit $E_BADARGS
fi

echo "Tracing Cupsd ... twice for $1 second intervals... "

sleep 5

echo "Running First Instance of Cupsd..."
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -rdtsc 1 -- /usr/sbin/cupsd -f -c /etc/cups/cupsd.conf &

sleep $1

echo "Killing cupsd"
killall cupsd

sleep 5 

echo "Moving trace.log to trace1.log"
mv trace.log trace1.log

sleep 10

echo "Running Second Instance of Cupsd..."
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -rdtsc 1 -- /usr/sbin/cupsd -f -c /etc/cups/cupsd.conf &

sleep $1

echo "Killing cupsd"
killall cupsd

sleep 5

echo "Moving trace.log to trace2.log"
mv trace.log trace2.log

sleep 10 

echo "Done"

