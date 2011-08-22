#! /bin/bash

EXPECTED_ARGS=5
if [ $# -ne $EXPECTED_ARGS ]
then
    echo "usage: {path to log1} {path to log2} {timing folder} {figures directory} {timing interval in seconds}"
    exit 0
fi

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Performing Diff (Suppress Common) on the Two Logs"

diff --side-by-side --suppress-common-lines --width=200 --minimal "$1" "$2" > "$3/diff_nocommon.log"

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done With Diff (Suppress Common)" 

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Performing Diff (Common + Uncommon) on the Two Logs"

diff --side-by-side --width=200 --minimal "$1" "$2" > "$3/diff.log"

currenttime=$(date +"%D %I:%M:%S %P")
echo "[$currenttime] Done With Diff (Common + Uncommon)"