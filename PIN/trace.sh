#! /bin/bash

EXPECTED_ARGS=1
E_BADARGS=65

if [ $# -lt $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {application_to_run}"
  exit $E_BADARGS
fi

echo "Tracing Application"
#/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -rdtsc 1 -canary 1 -guard 1 -- "$1"
#/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -- "$1"
/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -rdtsc 1 -memory 1 -- "$1"

echo "Done"

