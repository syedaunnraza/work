#!/bin/bash

EXPECTED_ARGS=4
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory}"
    exit 0
fi
currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running First Instance of Helloworld (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -sys 1 -pid 0 -stat 0 -time 0 -netinit 0 -epoll 0 -devrand 0 -rdtsc 0 -canary 0 -guard 0 -leader 1 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys1.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -fix_fork 0 -cpuid 0 -atraddr 0xbffff45b -sig 0 -signalfile "$3/signal.txt" -timex 0 -adjtimexfile "$3/timex.txt" -- /home/syed/Workspace/Samples/Helloworld/Helloworld) > "$3/output1.txt" 

#(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$1" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 0 -devrand 1 -rdtsc 1 -canary 1 -guard 1 -leader 1 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys1.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -fix_fork 1 -cpuid 1 -atraddr 0xbffff45b -sig 1 -signalfile "$3/signal.txt" -timex 1 -adjtimexfile "$3/timex.txt" -- /home/syed/Workspace/Samples/Helloworld/Helloworld) > "$3/output1.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with First Instance of Helloworld ..."

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Running Second Instance of Helloworld (to termination)..."

(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -sys 1 -pid 0 -stat 0 -time 0 -netinit 0 -epoll 0 -devrand 0 -rdtsc 0 -canary 0 -guard 0 -leader 0 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys2.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -cpuid 0 -fix_fork 0 -atraddr 0xbffff45b -sig 0 -signalfile "$3/signal.txt" -timex 0 -adjtimexfile "$3/timex.txt" -- /home/syed/Workspace/Samples/Helloworld/Helloworld) > "$3/output2.txt" 

#(LD_LIBRARY_PATH=/usr/lib/debug/ /home/syed/Workspace/Pin/pin -t /home/syed/Workspace/Pin/source/tools/DebugTrace/obj-ia32/debugtrace.so -o "$2" -sys 1 -pid 1 -stat 1 -time 1 -netinit 1 -epoll 0 -devrand 1 -rdtsc 1 -canary 1 -guard 1 -leader 0 -timefile "$3/time.txt" -dayfile "$3/day.txt" -print_func 1 -sysfile "$3/sys2.txt" -clockfile "$3/clock.txt" -epollfile "$3/epoll.txt" -memory 1 -cpuid 1 -fix_fork 1 -atraddr 0xbffff45b -sig 1 -signalfile "$3/signal.txt" -timex 1 -adjtimexfile "$3/timex.txt" -- /home/syed/Workspace/Samples/Helloworld/Helloworld) > "$3/output2.txt" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done with Second Instance of Helloworld (blocking call)..."

sleep 5

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Creating Diff Files for System Calls / Output"

diff --side-by-side --width=200 --suppress-common --minimal "$3/sys1.txt" "$3/sys2.txt" > "$3/sysdiff_sc.txt"
diff --side-by-side --width=200 --minimal "$3/sys1.txt" "$3/sys2.txt" > "$3/sysdiff.txt"
diff --side-by-side --width=200 --suppress-common --minimal "$3/output1.txt" "$3/output2.txt" > "$3/outdiff_sc.txt"
diff --side-by-side --width=200 --minimal "$3/output1.txt" "$3/output2.txt" > "$3/outdiff.txt"

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done"
