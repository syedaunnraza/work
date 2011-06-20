#! /bin/bash

EXPECTED_ARGS=0
E_BADARGS=65

if [ $# -lt $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {application_to_run}"
  exit $E_BADARGS
fi

echo "Tracing Application"

/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -optbb 1 -- /usr/sbin/cupsd -f -c /etc/cups/cupsd.conf
#/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -- /usr/sbin/cupsd -f -c /etc/cups/cupsd.conf

echo "Done"

