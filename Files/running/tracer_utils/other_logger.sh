#!/bin/bash

EXPECTED_ARGS=4
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory}"
    exit 0
fi
currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running First Instance (to termination)..."

# START ANACRON 
cp /var/spool/anacron/cron.daily "$3/cron.daily"
cp /var/spool/anacron/cron.weekly "$3/cron.weekly"
cp /var/spool/anacron/cron.monthly "$3/cron.monthly"
(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -sys 0 -pid 0 -stat 0 -time 0 -netinit 0 -epoll 0 -devrand 0 -rdtsc 0 -canary 0 -guard 0 -leader 1 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys1.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -fix_fork 0 -cpuid 0 -atraddr 0xbffff45b -sig 0 -signalfile "$3/signal.txt" -timex 0 -adjtimexfile "$3/timex.txt" -- /usr/sbin/anacron -d -n) > "$3/output1.txt" 
# END ANACRON

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with First Instance  ..."

sleep 2
currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running Second Instance (to termination)..."

#START ANACRON 
cp "$3/cron.daily" /var/spool/anacron/cron.daily
cp "$3/cron.weekly" /var/spool/anacron/cron.weekly
cp "$3/cron.monthly" /var/spool/anacron/cron.monthly
(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -sys 1 -pid 0 -stat 0 -time 0 -netinit 0 -epoll 0 -devrand 0 -rdtsc 0 -canary 0 -guard 0 -leader 0 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys2.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -cpuid 0 -fix_fork 0 -atraddr 0xbffff45b -sig 0 -signalfile "$3/signal.txt" -timex 0 -adjtimexfile "$3/timex.txt" -- /usr/sbin/anacron -n -d) > "$3/output2.txt" 
#END ANACRON

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with Second Instance (blocking call)..."

sleep 2

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done"
