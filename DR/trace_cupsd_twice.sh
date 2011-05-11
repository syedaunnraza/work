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
/home/syed/Workspace/DynamoRio/exports/bin32/drrun -client /home/syed/Workspace/DynamoRio/exports/samples/build/bin/libexecution_tracer.so 0 "" /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &
sleep $1

echo "Killing cupsd"
killall -9 cupsd

sleep 5 

echo "Moving trace.log to trace1.log"
mv trace.log trace1.log

sleep 10

echo "Running Second Instance of Cupsd..."
/home/syed/Workspace/DynamoRio/exports/bin32/drrun -client /home/syed/Workspace/DynamoRio/exports/samples/build/bin/libexecution_tracer.so 0 "" /home/syed/Workspace/Cupsd/build/sbin/cupsd -f &

sleep $1

echo "Killing cupsd"
killall -9 cupsd

sleep 5

echo "Moving trace.log to trace2.log"
mv trace.log trace2.log

sleep 10 

echo "Done"

