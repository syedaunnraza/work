#! /bin/bash

echo "Syncing Files"

echo "Copying .py Files in Diffwork/ into SyncedFiles/work/Comparison/"
cp /home/syed/Workspace/Diffwork/*.py /home/syed/Workspace/SyncedFiles/work/Comparison

echo "Copying .sh Files in Diffwork/ into SyncedFiles/work/Comparison/"
cp /home/syed/Workspace/Diffwork/*.sh /home/syed/Workspace/SyncedFiles/work/Comparison

echo "Copying .sh Files in Diffwork/PIN/ into SyncedFiles/work/PIN/"
cp /home/syed/Workspace/Diffwork/PIN/*.sh /home/syed/Workspace/SyncedFiles/work/PIN

echo "Copying .sh Files in Diffwork/DR/ into SyncedFiles/work/DR/"
cp /home/syed/Workspace/Diffwork/DR/*.sh /home/syed/Workspace/SyncedFiles/work/DR

echo "Copying debugtrace.cpp to SyncedFiles/work/DebugTrace/"
cp /home/syed/Workspace/Pin/source/tools/DebugTrace/debugtrace.cpp /home/syed/Workspace/SyncedFiles/work/DebugTrace

echo "Copying all DR tools to SyncedFiles/work/DR_tools/"
cp /home/syed/Workspace/DynamoRio/exports/samples/*.c /home/syed/Workspace/SyncedFiles/work/DR_Tools

echo "Copying Myself To SyncedFiles/work/Sync/"
cp /home/syed/Workspace/Diffwork/SYNC/*.sh /home/syed/Workspace/SyncedFiles/work/Sync

echo "Done"

