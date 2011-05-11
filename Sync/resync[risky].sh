#! /bin/bash

echo "FETCHING files from repository"

echo "Updating .py Files in Diffwork/ from SyncedFiles/work/Comparison/"
cp /home/syed/Workspace/SyncedFiles/work/Comparison/*.py /home/syed/Workspace/Diffwork 

echo "Updating .sh Files in Diffwork/ from SyncedFiles/work/Comparison/"
cp /home/syed/Workspace/SyncedFiles/work/Comparison/*.sh /home/syed/Workspace/Diffwork 

echo "Updating .sh Files in Diffwork/PIN/ from SyncedFiles/work/PIN/"
cp /home/syed/Workspace/SyncedFiles/work/PIN/*.sh /home/syed/Workspace/Diffwork/PIN
 
echo "Updating .sh Files in Diffwork/DR/ from SyncedFiles/work/DR/"
cp /home/syed/Workspace/SyncedFiles/work/DR/*.sh /home/syed/Workspace/Diffwork/DR 

echo "Updating debugtrace.cpp from SyncedFiles/work/DebugTrace/"
cp /home/syed/Workspace/SyncedFiles/work/DebugTrace/debugtrace.cpp /home/syed/Workspace/Pin/source/tools/DebugTrace 

echo "Updating all DR tools from SyncedFiles/work/DR_tools/"
cp /home/syed/Workspace/SyncedFiles/work/DR_Tools/*.c /home/syed/Workspace/DynamoRio/exports/samples

echo "Updating Myself from SyncedFiles/work/Sync/"
cp /home/syed/Workspace/SyncedFiles/work/Sync/*.sh /home/syed/Workspace/Diffwork/SYNC 

echo "Done"

