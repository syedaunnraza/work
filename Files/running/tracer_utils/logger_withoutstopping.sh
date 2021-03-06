#!/bin/bash

EXPECTED_ARGS=4
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory}"
    exit 0
fi

# FIXING /etc/resolv.conf
chattr +i /etc/resolv.conf
chattr +i /etc/hosts
chattr +i /etc/gai.conf

# UNFIXING /etc/resolv.conf
#chattr -i /etc/resolv.conf

# REMOVING FILES:
cat /var/cache/cups/job.cache > "$3/job.cache1.txt"
cat /var/cache/cups/remote.cache > "$3/remote.cache1.txt"
rm /var/log/cups/*

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running First Instance of Cupsd (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 1 -devrand 1 -rdtsc 1 -canary 0 -guard 0 -leader 1 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys1.txt" -epollfile "$3/epoll.txt" -memory 1 -fix_fork 1 -- /usr/sbin/cupsd -f -x 5) > "$3/output1.txt" 

#(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 1 -devrand 1 -rdtsc 1 -canary 0 -guard 0 -leader 1  -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys1.txt" -epollfile "$3/epoll.txt" -memory 1 -- /usr/sbin/cupsd -f -x 0) > "$3/output1.txt" 


currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with First Instance of Cupsd ..."

sleep 5

# REMOVING FILES
cat /var/cache/cups/job.cache > "$3/job.cache2.txt"
cat /var/cache/cups/remote.cache > "$3/remote.cache2.txt"
cp "$3/job.cache1.txt" /var/cache/cups/job.cache
cp "$3/remote.cache1.txt" /var/cache/cups/remote.cache 
rm /var/log/cups/*

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running Second Instance of Cupsd (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 1 -devrand 1 -rdtsc 1 -canary 0 -guard 0 -leader 0 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys2.txt" -epollfile "$3/epoll.txt" -memory 1 -fix_fork 1 -- /usr/sbin/cupsd -f -x 5) > "$3/output2.txt" 

#(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 1 -devrand 1 -rdtsc 1 -canary 0 -guard 0 -leader 0  -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys2.txt" -epollfile "$3/epoll.txt" -memory 1 -- /usr/sbin/cupsd -f -x 0) > "$3/output2.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with Second Instance of Cupsd (blocking call)..."

# FILE CHECK
cat /var/cache/cups/job.cache > "$3/cache3.txt"

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done Logging"

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Creating Diff Files for System Calls / Output"

diff --side-by-side --width=200 --suppress-common --minimal "$3/sys1.txt" "$3/sys2.txt" > "$3/sysdiff_sc.txt"
diff --side-by-side --width=200 --minimal "$3/sys1.txt" "$3/sys2.txt" > "$3/sysdiff.txt"
diff --side-by-side --width=200 --suppress-common --minimal "$3/output1.txt" "$3/output2.txt" > "$3/outdiff_sc.txt"
diff --side-by-side --width=200 --minimal "$3/output1.txt" "$3/output2.txt" > "$3/outdiff.txt"
