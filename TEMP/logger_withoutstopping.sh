#!/bin/bash

EXPECTED_ARGS=4
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory}"
    exit 0
fi

# REMOVING FILES:
# cat /home/syed/Workspace/Cupsd/build/var/cache/cups/job.cache > "$3/cache1.txt"
# rm /home/syed/Workspace/Cupsd/build//var/log/cups/access_log

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running First Instance of Cupsd (to termination)..."

#(/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -devrand 1 -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -leader 1  -time "$3/time1.txt" -day "$3/day1.txt" -print_func 0 -sys 1 -- /usr/sbin/cupsd -f) > "$3/output1.txt" 

(/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -devrand 0 -canary 0 -guard 0 -rdtsc 0 -pid 0 -memory 0 -leader 0  -time "$3/time1.txt" -day "$3/day1.txt" -print_func 0 -sys 0 -- /usr/sbin/cupsd -f) > "$3/output1.txt" 


currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with First Instance of Cupsd ..."

sleep 5

# REMOVING FILES
# cat /home/syed/Workspace/Cupsd/build/var/cache/cups/job.cache > "$3/cache2.txt"
# cp "$3/cache1.txt" /home/syed/Workspace/Cupsd/build/var/cache/cups/job.cache 
# rm /home/syed/Workspace/Cupsd/build//var/log/cups/access_log

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running Second Instance of Cupsd (to termination)..."

#(/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -devrand 1 -canary 1 -guard 1 -rdtsc 1 -pid 1 -memory 1 -leader 0 -time "$3/time1.txt" -day "$3/day1.txt" -print_func 0 -sys 1 -- /usr/sbin/cupsd -f) > "$3/output2.txt" 

(/home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -devrand 0 -canary 0 -guard 0 -rdtsc 0 -pid 0 -memory 0 -leader 0 -time "$3/time1.txt" -day "$3/day1.txt" -print_func 0 -sys 0 -- /usr/sbin/cupsd -f) > "$3/output2.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with Second Instance of Cupsd (blocking call)..."

# cat /home/syed/Workspace/Cupsd/build/var/cache/cups/job.cache > "$3/cache3.txt"

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done Logging"
