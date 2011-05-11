#! /bin/bash

EXPECTED_ARGS=1
E_BADARGS=65

if [ $# -lt $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {application_to_run}"
  exit $E_BADARGS
fi

echo "Tracing Application"
/home/syed/Workspace/DynamoRio/exports/bin32/drrun -logdir . -client /home/syed/Workspace/DynamoRio/exports/samples/build/bin/libexecution_tracer.so 0 "" "$1" 

echo "Done"

